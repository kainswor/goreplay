package tcp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var decodeOpts = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

func generateHeaders4(seq uint32, length uint16) (headers [54]byte) {
	// set ethernet headers
	binary.BigEndian.PutUint16(headers[12:14], uint16(layers.EthernetTypeIPv4))

	// set ip header
	ip := headers[14:]
	copy(ip[0:2], []byte{4<<4 | 5, 0x28<<2 | 0x00})
	binary.BigEndian.PutUint16(ip[2:4], length+54)
	ip[9] = uint8(layers.IPProtocolTCP)
	copy(ip[12:16], []byte{192, 168, 1, 2})
	copy(ip[16:], []byte{192, 168, 1, 3})

	// set tcp header
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 45678)
	binary.BigEndian.PutUint16(tcp[2:4], 8001)
	tcp[12] = 5 << 4
	return
}

func randomPackets(start uint32, _len int, length uint16) []gopacket.Packet {
	var packets = make([]gopacket.Packet, _len)
	for i := start; i < start+uint32(_len); i++ {
		d := make([]byte, length+54)
		h := generateHeaders4(i, length)
		copy(d, h[0:])
		packet := gopacket.NewPacket(d, layers.LinkTypeEthernet, decodeOpts)
		packets[i-start] = packet
	}
	return packets
}

// permutation using heap algorithm https://en.wikipedia.org/wiki/Heap%27s_algorithm
func permutation(a *[]*Packet, f func()) {
	n := len(*a)
	c := make([]int, n)
	f()
	i := 0
	for i < n {
		if c[i] < i {
			if i&1 != 1 {
				(*a)[0], (*a)[i] = (*a)[i], (*a)[0]
			} else {
				(*a)[c[i]], (*a)[i] = (*a)[i], (*a)[c[i]]
			}
			f()
			c[i]++
			i = 0
		} else {
			c[i] = 0
			i++
		}
	}
}

func TestOrderingChunkedWrongOrder(t *testing.T) {
	m := new(Message)
	m.packets = make([]*Packet, 4)
	var err error
	for i, v := range randomPackets(1, 4, 5) {
		m.packets[i], err = ParsePacket(v)
		if t != nil && err != nil {
			t.Errorf("%s", err)
		}
	}
	var ordered = func() {
		m.Sort()
		prev := m.packets[0].Seq
		for i := 0; i < len(m.packets); i++ {
			if prev > m.packets[i].Seq {
				t.Errorf("ordering packets failed")
				return
			}
		}
	}
	permutation(&m.packets, ordered)
}

func TestMessageParser(t *testing.T) {
	var mssg = make(chan *Message, 1)
	packets := randomPackets(1, 10, 63<<10)
	packets[0].Data()[34+13] = 2 // SYN flag
	packets[9].Data()[34+13] = 1 // FIN flag
	p := NewMessagePool(1<<20, time.Second*2, nil, func(m *Message) { mssg <- m })
	for _, v := range packets {
		p.Handler(v)
	}
	m := <-mssg
	if m.Length != 63<<10*10 || m.IPversion != 4 || m.done != nil {
		t.Errorf("failed to parse 30 packets in 100ms")
	}
}

func TestMessageRSTFlag(t *testing.T) {
	packet := randomPackets(1, 1, 5)[0]
	packet.Data()[34+13] = 4
	waiter := make(chan bool, 1)
	p := NewMessagePool(1<<20, 0, func(level int, a ...interface{}) {
		if level != 5 {
			t.Error("RST FLAG wrong level")
		}
		if d, ok := a[0].(string); !ok || d[0] != 'R' {
			t.Errorf("wrong message %s", d)
		}
		waiter <- true
	}, nil)
	p.Handler(packet)
	<-waiter
}

func TestPacketWithMissingMessage(t *testing.T) {
	packet := randomPackets(1, 1, 5)[0]
	waiter := make(chan bool, 1)
	p := NewMessagePool(1<<20, 0, func(level int, a ...interface{}) {
		if level != 5 {
			t.Error("wrong debug level")
		}
		if d, ok := a[0].(string); !ok || d[:6] != "packet" {
			t.Errorf("wrong message %s", d)
		}
		waiter <- true
	}, nil)
	p.Handler(packet)
	<-waiter
}

func TestMessageUUID(t *testing.T) {
	m1 := &Message{}
	pckt1 := &Packet{}
	pckt1.TCP = new(layers.TCP)
	pckt1.Seq = 2
	m1.packets = []*Packet{pckt1}
	m1.IsIncoming = true
	m1.SrcAddr = "src"
	m1.DstAddr = "dst"
	m2 := &Message{}
	pckt2 := &Packet{}
	pckt2.TCP = new(layers.TCP)
	pckt2.Ack = pckt1.Seq + 1
	m2.SrcAddr = "dst"
	m2.DstAddr = "src"
	m2.packets = []*Packet{pckt2}
	if string(m1.UUID()) != string(m2.UUID()) {
		t.Errorf("expected %s, to equal %s", m1.UUID(), m2.UUID())
	}
}
func BenchmarkMessageReassembling(b *testing.B) {
	var mssg = make(chan *Message, 1)
	if b.N < 3 {
		return
	}
	b.StopTimer()
	now := time.Now()
	n := b.N
	packets := randomPackets(1, n, 10)
	packets[0].Data()[34+13] = 2     // SYN flag
	packets[b.N-1].Data()[34+13] = 1 // FIN flag
	p := NewMessagePool(1<<20, time.Second*2, nil, func(m *Message) {
		b.Logf("%d/%d packets in %s", len(m.packets), n, time.Since(now))
		mssg <- m
	})
	b.StartTimer()
	for _, v := range packets {
		p.Handler(v)
	}
	<-mssg
}

func BenchmarkPacketParseAndSort(b *testing.B) {
	if b.N < 3 {
		return
	}
	now := time.Now()
	m := new(Message)
	m.packets = make([]*Packet, b.N)
	for i, v := range randomPackets(1, b.N, 1) {
		m.packets[i], _ = ParsePacket(v)
	}
	m.Sort()
	b.Logf("%d packets in %s", b.N, time.Since(now))
}
