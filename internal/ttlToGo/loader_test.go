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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var LoadFailed atomic.Bool

func mapIPs() []MapIP {
	return []MapIP{
		{0, "fd01::ff"},
		{1, "fd01::ee"},
		{2, "fd01::dd"},
		{3, "fd01::cc"},
		{4, "fd01::bb"},
	}
}

func (o *bpfObjects) setMapIPs(t *testing.T) {
	for _, ip := range mapIPs() {
		o.setAddr(t, ip.hopLimit, ip.addr)
	}
}

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

func packet(hopLimit int, dstAddr string) []byte {
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
		SrcIP: net.ParseIP("fd03::4"),
		DstIP: net.ParseIP(dstAddr),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit: uint8(hopLimit),
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

func icmp6Checksum(t *testing.T, src, dst string, length int) uint16 {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	ipv6 := layers.IPv6{
		SrcIP: net.ParseIP(src),
		DstIP: net.ParseIP(dst),
		NextHeader: layers.IPProtocolICMPv6,
	}

	icmp6 := layers.ICMPv6 {
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, 0),
	}

	p := make([]byte, 0)
	for i := 4; i < length; i++ {
		p = append(p, 0xff)
	}

	payload := gopacket.Payload(p)

	icmp6.SetNetworkLayerForChecksum(&ipv6)
	err := gopacket.SerializeLayers(buf, opts, &ipv6, &icmp6, &payload)
	require.NoError(t, err)

	outPkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	outLayers := outPkt.Layers()
	ip6out, ok := outLayers[0].(*layers.IPv6)
	require.True(t, ok, "decode ip for checksum")
	require.Equal(t, uint16(length), ip6out.Length, "decode ip for checksum")
	icmp6out, ok := outLayers[1].(*layers.ICMPv6)
	require.True(t, ok, "decode icmp for checksum")

	return icmp6out.Checksum
}

func load(tb testing.TB) *bpfObjects {
	if LoadFailed.Load() {
		tb.Fatal("Fail due to previous load errors")
	}

	objs, err := Load()
	if err == nil {
		tb.Cleanup(func() { objs.Close() })
		return objs
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
	if err := o.SetAddr(idx, addr); err != nil {
		t.Fatalf("map load error: %v", err)
	}
}

func (o *bpfObjects) statsPrint(t *testing.T) {
	var nextKey uint32
	var lookupKeys   = make([]uint32, 8)
	var lookupValues = make([]uint32, 8)
	o.TtlCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

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
	for _, ip := range mapIPs() {
		t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(tt *testing.T) {
			objs := load(tt)
			objs.setMapIPs(tt)

			pkt := packet(ip.hopLimit, mapIPs()[0].addr)
			ret, out, err := objs.XdpTtltogo.Test(pkt)
			require.NoError(tt, err, "program must run without error")
			assert.Equal(tt, 3, int(ret), "return code must be XDP_TX(3)")
			outPkt := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			outLayers := outPkt.Layers()
			require.Equal(tt, 4, len(outLayers), "number of layers must be correct")

			ip6, ok := outLayers[1].(*layers.IPv6)
			if assert.True(tt, ok, "must be IPv6") {
				assert.Equal(tt, ip.addr, ip6.SrcIP.String(), "correct src address needed")
				assert.Equal(tt, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
				assert.Equal(tt, 64, int(ip6.Length), "correct length needed")
				assert.Equal(tt, 6, int(ip6.Version), "correct version needed")
				assert.Equal(tt, 64, int(ip6.HopLimit), "correct hop limit needed")
				assert.Equal(tt, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
			}

			icmp6, ok := outLayers[2].(*layers.ICMPv6)
			if assert.True(tt, ok, "must be ICMPv6") {
				assert.Equal(tt, "TimeExceeded(HopLimitExceeded)", icmp6.TypeCode.String())
				assert.Equal(tt, icmp6Checksum(tt, ip.addr, "fd03::4", 64), icmp6.Checksum, "checksum must match")
			}
		})
	}
}

func TestNoMatch(t *testing.T) {
	ips := []MapIP{
		{42,"fd0f::ff"},
		{12,"fe80::1"},
		{1,"1234:dead:beef:c0ff:ee:101::ff"},
	}

	for _, ip := range ips {
		t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(tt *testing.T) {
			objs := load(tt)
			objs.setMapIPs(tt)

			pkt := packet(ip.hopLimit, ip.addr)
			ret, out, err := objs.XdpTtltogo.Test(pkt)
			require.NoError(tt, err, "program must run without error")
			assert.Equal(tt, 2, int(ret), "return code must be XDP_PASS(2)")
			assert.Equal(tt, pkt, out, "output package must be the same as input")
		})
	}
}
