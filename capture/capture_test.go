package capture

import (
	"context"
	"encoding/binary"
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LoopBack = func() net.Interface {
	ifis, _ := net.Interfaces()
	for _, v := range ifis {
		if v.Flags&net.FlagLoopback != 0 {
			return v
		}
	}
	return ifis[0]
}()

func TestListenerInvalidTransport(t *testing.T) {
	l, _ := NewListener("", 10, "udp", 0, false)
	if l.Transport != "tcp" {
		t.Errorf("expected transport to be tcp, got %s", l.Transport)
	}
	if l.Engine != EnginePcap {
		t.Errorf("expected engine to be %s, got %s", EnginePcap, l.Engine)
	}
}

func TestSetInterfaces(t *testing.T) {
	l := &Listener{}
	l.addr = "127.0.0.1"
	l.setInterfaces()
	if len(l.Interfaces) != 1 {
		t.Error("expected a single interface")
	}
	l.addr = LoopBack.HardwareAddr.String()
	l.setInterfaces()
	if l.Interfaces[0].Name != LoopBack.Name && len(l.Interfaces) != 1 {
		t.Error("interface should be loop back interface")
	}
	l.addr = ""
	l.setInterfaces()
	if len(l.Interfaces) < 1 {
		t.Error("should get all interfaces")
	}
}

func TestBPFFilter(t *testing.T) {
	l := &Listener{}
	l.addr = "127.0.0.1"
	l.Transport = "tcp"
	l.setInterfaces()
	filter := l.Filter(l.Interfaces[0])
	if filter != "(tcp dst portrange 0-65535 and host 127.0.0.1)" {
		t.Error("wrong filter", filter)
	}
	l.port = 8000
	l.trackResponse = true
	filter = l.Filter(l.Interfaces[0])
	if filter != "(tcp port 8000 and host 127.0.0.1)" {
		t.Error("wrong filter")
	}
}

var decodeOpts = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

func generateHeaders(seq uint32, length uint16) (headers [44]byte) {
	// set ethernet headers
	binary.BigEndian.PutUint32(headers[0:4], uint32(layers.ProtocolFamilyIPv4))

	// set ip header
	ip := headers[4:]
	copy(ip[0:2], []byte{4<<4 | 5, 0x28<<2 | 0x00})
	binary.BigEndian.PutUint16(ip[2:4], length+54)
	ip[9] = uint8(layers.IPProtocolTCP)
	copy(ip[12:16], []byte{127, 0, 0, 1})
	copy(ip[16:], []byte{127, 0, 0, 1})

	// set tcp header
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 45678)
	binary.BigEndian.PutUint16(tcp[2:4], 8000)
	tcp[12] = 5 << 4
	return
}

func randomPackets(start uint32, _len int, length uint16) []gopacket.Packet {
	var packets = make([]gopacket.Packet, _len)
	for i := start; i < start+uint32(_len); i++ {
		h := generateHeaders(i, length)
		d := make([]byte, int(length)+len(h))
		copy(d, h[0:])
		packet := gopacket.NewPacket(d, layers.LinkTypeLoop, decodeOpts)
		packets[i-start] = packet
		inf := packets[i-start].Metadata()
		_len := len(d)
		inf.CaptureInfo = gopacket.CaptureInfo{CaptureLength: _len, Length: _len, Timestamp: time.Now()}
	}
	return packets
}

func TestPcapDump(t *testing.T) {
	f, err := ioutil.TempFile("", "pcap_file")
	if err != nil {
		t.Error(err)
	}
	waiter := make(chan bool, 1)
	h, _ := PcapDumpHandler(f, layers.LinkTypeLoop, func(level int, a ...interface{}) {
		if level != 3 {
			t.Errorf("expected debug level to be 3, got %d", level)
		}
		waiter <- true
	})
	packets := randomPackets(1, 5, 5)
	for i := 0; i < len(packets); i++ {
		if i == 1 {
			tcp := packets[i].Data()[4:][20:]
			// change dst port
			binary.BigEndian.PutUint16(tcp[2:], 8001)
		}
		if i == 4 {
			inf := packets[i].Metadata()
			inf.CaptureLength = 40
		}
		h(packets[i])
	}
	<-waiter
	name := f.Name()
	f.Close()
	testPcapDumpEngine(name, t)
}

func testPcapDumpEngine(f string, t *testing.T) {
	defer os.Remove(f)
	l, err := NewListener(f, 8000, "", EnginePcapFile, true)
	err = l.Activate()
	if err != nil {
		t.Errorf("expected error to be nil, got %q", err)
		return
	}
	pckts := 0
	err = l.Listen(context.Background(), func(packet gopacket.Packet) {
		if packet.Metadata().CaptureLength != 49 {
			t.Errorf("expected packet length to be %d, got %d", 49, packet.Metadata().CaptureLength)
		}
		pckts++
	})

	if err != nil {
		t.Errorf("expected error to be nil, got %q", err)
	}
	if pckts != 3 {
		t.Errorf("expected %d packets, got %d packets", 3, pckts)
	}
}

func TestPcapHandler(t *testing.T) {
	l, err := NewListener(LoopBack.Name, 8000, "", EnginePcap, true)
	if err != nil {
		t.Errorf("expected error to be nil, got %d", err)
		return
	}
	if err != nil {
		t.Errorf("expected error to be nil, got %v", err)
		return
	}
	if err != nil {
		t.Errorf("expected error to be nil, got %v", err)
		return
	}
	pckts := 0
	errCh := l.ListenBackground(context.Background(), func(packet gopacket.Packet) {
		if packet.Metadata().CaptureLength != 49 {
			t.Errorf("expected packet length to be %d, got %d", 49, packet.Metadata().CaptureLength)
		}
		pckts++
	})
	packets := randomPackets(1, 5, 5)
	for i := 0; i < 5; i++ {
		l.packets <- packets[i]
	}
	close(l.packets)
	err = <-errCh
	if pckts != 5 {
		t.Errorf("expected %d packets, got %d packets", 5, pckts)
	}
	if err != nil {
		t.Errorf("expected error to be nil, got %d", err)
		return
	}
}

func BenchmarkPcapDump(b *testing.B) {
	f, err := ioutil.TempFile("", "pcap_file")
	if err != nil {
		b.Error(err)
		return
	}
	now := time.Now()
	defer os.Remove(f.Name())
	h, _ := PcapDumpHandler(f, layers.LinkTypeLoop, nil)
	packets := randomPackets(1, b.N, 5)
	for i := 0; i < len(packets); i++ {
		h(packets[i])
	}
	f.Close()
	b.Logf("%d packets in %s", b.N, time.Since(now))
}

func BenchmarkPcapFile(b *testing.B) {
	b.StopTimer()
	f, err := ioutil.TempFile("", "pcap_file")
	if err != nil {
		b.Error(err)
		return
	}
	defer os.Remove(f.Name())
	h, _ := PcapDumpHandler(f, layers.LinkTypeLoop, nil)
	packets := randomPackets(1, b.N, 5)
	for i := 0; i < len(packets); i++ {
		h(packets[i])
	}
	name := f.Name()
	f.Close()
	var l *Listener
	l, err = NewListener(name, 8000, "", EnginePcapFile, true)
	if err != nil {
		b.Error(err)
		return
	}
	l.Activate()
	b.StartTimer()
	now := time.Now()
	pckts := 0
	if err = l.Listen(context.Background(), func(packet gopacket.Packet) {
		if packet.Metadata().CaptureLength != 49 {
			b.Errorf("expected packet length to be %d, got %d", 49, packet.Metadata().CaptureLength)
		}
		pckts++
	}); err != nil {
		b.Error(err)
	}
	b.Logf("%d/%d packets in %s", pckts, b.N, time.Since(now))
}

func BenchmarkPcap(b *testing.B) {
	l, err := NewListener(LoopBack.Name, 8000, "", EnginePcap, true)
	if err != nil {
		b.Errorf("expected error to be nil, got %d", err)
		return
	}
	if err != nil {
		b.Errorf("expected error to be nil, got %v", err)
		return
	}
	if err != nil {
		b.Errorf("expected error to be nil, got %v", err)
		return
	}
	now := time.Now()
	pckts := 0
	errCh := l.ListenBackground(context.Background(), func(packet gopacket.Packet) {
		if packet.Metadata().CaptureLength != 49 {
			b.Errorf("expected packet length to be %d, got %d", 49, packet.Metadata().CaptureLength)
		}
		pckts++
	})
	packets := randomPackets(1, b.N, 5)
	for i := 0; i < b.N; i++ {
		l.packets <- packets[i]
	}
	close(l.packets)
	err = <-errCh
	if pckts != b.N {
		b.Errorf("expected %d packets, got %d packets", 5, pckts)
	}
	if err != nil {
		b.Errorf("expected error to be nil, got %d", err)
		return
	}
	b.Logf("%d packets in %s", b.N, time.Since(now))
}
