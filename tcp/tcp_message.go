package tcp

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/buger/goreplay/size"
	"github.com/google/gopacket"
)

// Stats every message carry its own stats object
type Stats struct {
	LostData    int
	Length      int       // length of the data
	Start       time.Time // first packet's timestamp
	End         time.Time // last packet's timestamp
	IPversion   uint8
	WindowScale uint16
	MSS         uint16 // maximum segment size
	SrcAddr     string
	DstAddr     string
}

// Message is the representation of a tcp message
type Message struct {
	sync.Mutex
	Stats

	IsIncoming bool

	packets []*Packet
	done    chan bool
}

// NewMessage ...
func NewMessage(isIncoming bool, srcAddr, dstAddr string, ipVersion uint8) (m *Message) {
	m = new(Message)
	m.IsIncoming = isIncoming
	m.DstAddr = dstAddr
	m.SrcAddr = srcAddr
	m.IPversion = ipVersion
	m.done = make(chan bool, 1)
	return
}

// UUID probably the unique id of a message(presumably both request and response)
func (m *Message) UUID() []byte {
	m.Lock()
	defer m.Unlock()
	if len(m.packets) == 0 {
		return nil
	}
	var syn uint32 // the initial sequence number of a request
	var src, dst string
	if m.IsIncoming {
		syn = m.packets[0].Seq
		src = m.SrcAddr
		dst = m.DstAddr
	} else {
		syn = m.packets[0].Ack - 1
		src = m.DstAddr
		dst = m.SrcAddr
	}

	length := 4 + len(src) + len(dst)
	uuid := make([]byte, length)
	binary.BigEndian.PutUint32(uuid, syn)
	copy(uuid[4:], src)
	copy(uuid[4:][len(src):], dst)
	sha := sha1.Sum(uuid)
	uuid = make([]byte, 40)
	hex.Encode(uuid, sha[:])

	return uuid
}

func (m *Message) add(pckt *Packet) {
	m.Length += len(pckt.Payload)
	m.LostData += int(pckt.Lost)
	m.packets = append(m.packets, pckt)
	if m.Start.Nanosecond() == 0 {
		m.Start = pckt.Timestamp
	}
	m.End = pckt.Timestamp
	if pckt.FIN {
		m.done <- true
	}
}

// Packets returns packets of this message
func (m *Message) Packets() []*Packet {
	m.Lock()
	defer m.Unlock()
	return m.packets
}

// Bytes returns data inside each packets
func (m *Message) Bytes() (data [][]byte) {
	for _, pckt := range m.Packets() {
		if len(pckt.Payload) > 0 {
			data = append(data, pckt.Payload)
		}
	}
	return
}

// Data returns data in this message
func (m *Message) Data() []byte {
	return bytes.Join(m.Bytes(), []byte{})
}

// Sort a helper to sort packets
func (m *Message) Sort() {
	sort.SliceStable(m.packets, func(i, j int) bool { return m.packets[i].Seq < m.packets[j].Seq })
}

// Handler message handler
type Handler func(*Message)

// Debugger is the debugger function. first params is the indicator of the issue's priority
// the higher the number, the lower the priority. it can be 4 <= level <= 6.
type Debugger func(int, ...interface{})

// MessagePool holds data of all tcp messages in progress(still receiving/sending packets).
// Incoming message is identified by the its source port and address e.g: 127.0.0.1:45785.
// The outgoing message is identified by  server.addr and dst.addr e.g: localhost:80=internet:45785.
type MessagePool struct {
	sync.Mutex
	debug         Debugger
	maxSize       size.Size // maximum message size, default 5mb
	pool          map[string]*Message
	handler       Handler
	messageExpire time.Duration // the maximum time to wait for the final packet, minimum is 100ms
}

// NewMessagePool returns a new instance of message pool
func NewMessagePool(maxSize size.Size, messageExpire time.Duration, debugger Debugger, handler Handler) (pool *MessagePool) {
	pool = new(MessagePool)
	pool.debug = debugger
	pool.handler = handler
	pool.messageExpire = time.Millisecond * 100
	if pool.messageExpire < messageExpire {
		pool.messageExpire = messageExpire
	}
	pool.maxSize = maxSize
	if pool.maxSize < 1 {
		pool.maxSize = 5 << 20
	}
	pool.pool = make(map[string]*Message)
	return pool
}

// Handler returns packet handler
func (pool *MessagePool) Handler(packet gopacket.Packet) {
	pckt, err := ParsePacket(packet)
	if err != nil && len(pckt.Payload) == 0 {
		go pool.say(4, fmt.Sprintf("error decoding packet(%dByte):%s\n", packet.Metadata().CaptureLength, err))
		return
	}
	if pckt.RST {
		go pool.say(5, fmt.Sprintf("RST flag sent to %s from %s\n", pckt.Src(), pckt.Dst()))
		return
	}
	pool.Lock()
	srcAddr := pckt.Src()
	// creating new message
	if pckt.SYN {
		isIncoming := pckt.SYN && !pckt.ACK
		key := srcAddr
		if !isIncoming {
			key += ("=" + pckt.Dst())
		}
		m := NewMessage(isIncoming, srcAddr, pckt.Dst(), pckt.Version())
		m.MSS, m.WindowScale = pckt.SYNOptions()
		pool.pool[key] = m
		go pool.timer(m, key)
	}
	m, ok := pool.pool[srcAddr]
	if !ok {
		m, ok = pool.pool[srcAddr+"="+pckt.Dst()]
	}
	pool.Unlock()
	if ok {
		ok = pool.addPacket(m, pckt)
		if ok {
			go pool.say(6, fmt.Sprintf("message: %s, packet:\n%s\n", m.SrcAddr, pckt))
			return
		}
	}
	go pool.say(5, fmt.Sprintf("packet from %s with length(%dB) discarded\n", srcAddr, len(pckt.Payload)))

}

func (pool *MessagePool) dispatch(key string, m *Message) {
	m.Lock()
	pool.Lock()
	delete(pool.pool, key)
	pool.Unlock()
	m.Sort()
	m.done = nil
	m.Unlock()
	pool.handler(m)
}

func (pool *MessagePool) addPacket(m *Message, pckt *Packet) bool {
	m.Lock()
	defer m.Unlock()
	// checking if message was not dispatched alread
	if m.done == nil {
		return false
	}
	if m.Length+len(pckt.Payload) >= int(pool.maxSize) {
		m.done <- true
		return false
	}
	m.add(pckt)
	return true
}

func (pool *MessagePool) timer(m *Message, key string) {
	t := time.NewTicker(pool.messageExpire)
	defer t.Stop()
	select {
	case <-m.done:
	case <-t.C:
	}
	pool.dispatch(key, m)
}

// this function should not block other pool operations
func (pool *MessagePool) say(level int, args ...interface{}) {
	if pool.debug != nil {
		pool.debug(level, args...)
	}
}
