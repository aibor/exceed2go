package ttlToGo

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LoadFailed atomic.Bool

func mountfs(m *testing.M, path, fstype string) error {
	if (os.Getpid() != 1) {
		return nil
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %v", path, err)
	}

	if err := syscall.Mount("", path, fstype, 0, ""); err != nil {
		return fmt.Errorf("mount %s: %v", path, err)
	}

	return nil
}

func poweroff() {
	if (os.Getpid() != 1) {
		return
	}

	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}

func run(m *testing.M) int {
	defer poweroff()
	fmt.Println("Init")

	mounts := map[string]string{
		"/sys": "sysfs",
		"/sys/kernel/tracing": "tracefs",
		"/proc": "proc",
	}

	for mp, t := range mounts {
		if err := mountfs(m, mp, t); err != nil {
			fmt.Println(err)
			return 1
		}
		time.Sleep(200 * time.Millisecond)
	}

	if err := os.WriteFile("/proc/sys/kernel/printk", []byte("0"), 0755); err != nil {
		fmt.Printf("setting printk: %v\n", err)
		return 1
	}

	fmt.Println("Run tests")
	ret := m.Run()
	fmt.Println("Print trace")
	f, err := os.ReadFile("/sys/kernel/tracing/trace")
	if err != nil {
		fmt.Printf("error opening trace pipe: %v\n", err)
		return ret
	}

	for _, l := range strings.Split(string(f), "\n") {
		if !strings.HasPrefix(l, "#") {
			fmt.Println(l)
		}
	}

	return ret
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func packet() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6 := layers.IPv6{
		Version: uint8(6),
		SrcIP: net.ParseIP("fd01::4"),
		DstIP: net.ParseIP("fd01::ff"),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit: uint8(1),
	}

	icmp6 := layers.ICMPv6 {
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmp6echo := layers.ICMPv6Echo {
		Identifier: 1,
		SeqNumber: 1,
	}

	payload := gopacket.Payload([]byte{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4})
	icmp6.SetNetworkLayerForChecksum(&ipv6)

	gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &icmp6, &icmp6echo, &payload)

	return buf.Bytes()
}

func load(tb testing.TB) *bpfObjects {
	if LoadFailed.Load() {
		tb.Fatal("Fail due to previous load errors")
	}

	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err == nil {
		return &objs
	}

	tb.Errorf("error loading objects: %v", err)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		tb.Logf("verifier log:\n %s", strings.Join(ve.Log, "\n"))
	}

	LoadFailed.Store(true)
	tb.FailNow()

	return nil
}

func (o *bpfObjects) setAddr(t *testing.T, idx int, addr string) {
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("must parse: %s", addr)
	}
	if err := o.TtlAddrs.Put(uint32(idx), []byte(ip)); err != nil {
		t.Fatalf("map load error: %v", err)
	}
}

func statsPrint(t *testing.T, objs *bpfObjects) {
	var nextKey uint32
	var lookupKeys   = make([]uint32, 8)
	var lookupValues = make([]uint32, 8)
	objs.TtlCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

	t.Logf("  Index: % d", lookupKeys)
	t.Logf("Counter: % d", lookupValues)
}

func pktPrint(t *testing.T, pkt []byte) {
	t.Logf("length: %d", len(pkt))
	for i := 0; i < len(pkt); i += 16 {
		var out []byte
		if e := i + 16; e >= len(pkt) {
			out = pkt[i:]
		} else {
			out = pkt[i:e]
		}
		t.Logf("%d: % x\n", i/16, out)
	}
}

func TestLoad(t *testing.T) {
	objs := load(t)
	objs.Close()
}

func TestTTL(t *testing.T) {
	objs := load(t)
	defer objs.Close()

	objs.setAddr(t, 0, "fd01::ff")
	objs.setAddr(t, 1, "fd01::ee")

	pkt := packet()
	pktPrint(t, pkt)

	ret, out, err := objs.XdpTtltogo.Test(pkt)
	if err != nil {
		t.Fatalf("test error: %v", err)
	}

	statsPrint(t, objs)
	pktPrint(t, out)

	if ret != 3 {
		t.Fatalf("wrong return value: %d", ret)
	}
}
