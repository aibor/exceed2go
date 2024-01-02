package bpf_test

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aibor/exceed2go/internal/bpf"
)

var LoadFailed atomic.Bool
var timeExceededTC = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, 0)
var echoReplyTC = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)

type MapIP struct {
	hopLimit int
	addr     string
}

func mapIPs() []MapIP {
	return []MapIP{
		{1, "fd01::bb"},
		{2, "fd01::cc"},
		{3, "fd01::dd"},
		{4, "fd01::ee"},
		{5, "fd01::ff"},
	}
}

func setMapIPs(tb testing.TB, config *ebpf.Map) {
	tb.Helper()

	for _, ip := range mapIPs() {
		setAddr(tb, config, ip.hopLimit, ip.addr)
	}
}

func packet(tb testing.TB, hopLimit int, dstAddr string, payload []byte) []byte {
	tb.Helper()

	if len(payload) == 0 {
		payload = []byte{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC:       net.HardwareAddr{0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ipv6 := layers.IPv6{
		Version:    uint8(6),
		SrcIP:      net.ParseIP("fd03::4"),
		DstIP:      net.ParseIP(dstAddr),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   uint8(hopLimit),
	}

	icmp6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	icmp6echo := layers.ICMPv6Echo{
		Identifier: 1,
		SeqNumber:  1,
	}

	pload := gopacket.Payload(payload)
	err := icmp6.SetNetworkLayerForChecksum(&ipv6)
	require.NoError(tb, err, "must set layer for checksum")

	err = gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &icmp6, &icmp6echo, &pload)
	require.NoError(tb, err, "must serialize packet")

	return buf.Bytes()
}

func icmp6Checksum(tb testing.TB, src, dst string, icmp6TypeCode layers.ICMPv6TypeCode, payload []byte) uint16 {
	tb.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipv6 := layers.IPv6{
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
		NextHeader: layers.IPProtocolICMPv6,
	}

	icmp6 := layers.ICMPv6{
		TypeCode: icmp6TypeCode,
	}

	pload := gopacket.Payload(payload)

	err := icmp6.SetNetworkLayerForChecksum(&ipv6)
	require.NoError(tb, err, "must set layer for checksum")
	err = gopacket.SerializeLayers(buf, opts, &ipv6, &icmp6, &pload)
	require.NoError(tb, err, "must serialize packet")

	outPkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	outLayers := outPkt.Layers()
	icmp6out, ok := outLayers[1].(*layers.ICMPv6)
	require.True(tb, ok, "decode icmp for checksum")

	return icmp6out.Checksum
}

func load(tb testing.TB) *bpf.Exceed2GoObjects {
	tb.Helper()

	if LoadFailed.Load() {
		tb.Fatal("Fail due to previous load errors")
	}

	objs := &bpf.Exceed2GoObjects{}
	err := bpf.LoadExceed2GoObjects(objs, nil)
	tb.Cleanup(func() {
		if objs != nil {
			objs.Close()
		}
	})
	if err == nil {
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

func setAddr(tb testing.TB, config *ebpf.Map, idx int, addr string) {
	tb.Helper()

	if err := config.Put(uint32(idx), netip.MustParseAddr(addr).AsSlice()); err != nil {
		tb.Fatalf("map load error: %v", err)
	}
}

func statsPrint(tb testing.TB, stats *ebpf.Map) {
	tb.Helper()

	var cursor ebpf.BatchCursor
	var lookupKeys = make([]uint32, stats.MaxEntries())
	var lookupValues = make([]uint32, stats.MaxEntries())
	_, _ = stats.BatchLookup(&cursor, lookupKeys, lookupValues, nil)

	for idx, key := range lookupKeys {
		tb.Logf("%-25s  %d", bpf.Exceed2GoCounterKey(key), lookupValues[idx])
	}
}

func testProg(tb testing.TB, prog *ebpf.Program, pkt []byte, rc uint32) gopacket.Packet {
	tb.Helper()

	ret, out, err := prog.Test(pkt)
	require.NoError(tb, err, "program must run without error")
	assert.Equal(tb, rc, ret, "return code should be correct")

	return gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
}

type getProgFunc func(*bpf.Exceed2GoObjects) *ebpf.Program

func getXDPProg(objs *bpf.Exceed2GoObjects) *ebpf.Program {
	return objs.Exceed2goXdp
}

func getTCProg(objs *bpf.Exceed2GoObjects) *ebpf.Program {
	return objs.Exceed2goTc
}

type progTest struct {
	getProgFunc getProgFunc
	redirectRC  uint32
	passRC      uint32
}

var progTests = map[string]progTest{
	"xdp": {
		getProgFunc: getXDPProg,
		redirectRC:  3,
		passRC:      2,
	},
	"tc": {
		getProgFunc: getTCProg,
		redirectRC:  7,
		passRC:      math.MaxUint32,
	},
}

func TestTTL(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			objs := load(t)
			setMapIPs(t, objs.Exceed2goAddrs)

			for idx, ip := range mapIPs() {
				if idx == 4 {
					continue
				}

				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					pkt := packet(t, ip.hopLimit, mapIPs()[4].addr, []byte{})
					outPkt := testProg(t, test.getProgFunc(objs), pkt, test.redirectRC)
					outLayers := outPkt.Layers()
					require.Equal(t, 4, len(outLayers), "number of layers must be correct")

					ip6, ok := outLayers[1].(*layers.IPv6)
					if assert.True(t, ok, "must be IPv6") {
						assert.Equal(t, ip.addr, ip6.SrcIP.String(), "correct src address needed")
						assert.Equal(t, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
						assert.Equal(t, 64, int(ip6.Length), "correct length needed")
						assert.Equal(t, 6, int(ip6.Version), "correct version needed")
						assert.Equal(t, 64, int(ip6.HopLimit), "correct hop limit needed")
						assert.Equal(t, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
					}

					icmp6, ok := outLayers[2].(*layers.ICMPv6)
					if assert.True(t, ok, "must be ICMPv6") {
						assert.Equal(t, "TimeExceeded(HopLimitExceeded)", icmp6.TypeCode.String())
						expectedChecksum := icmp6Checksum(t, ip.addr, "fd03::4", timeExceededTC, outPkt.Data()[58:])
						assert.Equal(t, expectedChecksum, icmp6.Checksum, "checksum must match")
					}
				})
			}
			if t.Failed() {
				statsPrint(t, objs.Exceed2goCounters)
			}
		})
	}
}

func TestTTLMaxSize(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			objs := load(t)
			setMapIPs(t, objs.Exceed2goAddrs)

			payloads := []struct {
				truncated bool
				payload   []byte
			}{
				{false, []byte{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4}},
				{false, make([]byte, 1182)},
				{false, make([]byte, 1183)},
				{false, make([]byte, 1184)},
				{true, make([]byte, 1185)},
				{true, make([]byte, 1186)},
				{true, make([]byte, 1187)},
				{true, make([]byte, 1400)},
			}

			for _, payload := range payloads {
				t.Run(fmt.Sprintf("payload size %d", len(payload.payload)), func(t *testing.T) {
					ip := mapIPs()[0]
					pktSize := (len(payload.payload) & ^3) + 110
					if payload.truncated {
						pktSize = 1294
					}

					pkt := packet(t, 1, mapIPs()[4].addr, payload.payload)
					outPkt := testProg(t, test.getProgFunc(objs), pkt, test.redirectRC)
					assert.Equal(t, pktSize, len(outPkt.Data()), "out package must have correct length")
					outLayers := outPkt.Layers()
					require.Equal(t, 4, len(outLayers), "number of layers must be correct")

					ip6, ok := outLayers[1].(*layers.IPv6)
					if assert.True(t, ok, "must be IPv6") {
						assert.Equal(t, ip.addr, ip6.SrcIP.String(), "correct src address needed")
						assert.Equal(t, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
						assert.Equal(t, pktSize-54, int(ip6.Length), "correct length needed")
						assert.Equal(t, 6, int(ip6.Version), "correct version needed")
						assert.Equal(t, 64, int(ip6.HopLimit), "correct hop limit needed")
						assert.Equal(t, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
					}

					icmp6, ok := outLayers[2].(*layers.ICMPv6)
					if assert.True(t, ok, "must be ICMPv6") {
						assert.Equal(t, "TimeExceeded(HopLimitExceeded)", icmp6.TypeCode.String())
						expectedChecksum := icmp6Checksum(t, ip.addr, "fd03::4", timeExceededTC, outPkt.Data()[58:])
						assert.Equal(t, expectedChecksum, icmp6.Checksum, "checksum must match")
					}
				})
			}
			if t.Failed() {
				statsPrint(t, objs.Exceed2goCounters)
			}
		})
	}
}

func TestNoMatch(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			objs := load(t)
			setMapIPs(t, objs.Exceed2goAddrs)

			ips := []MapIP{
				{42, "fd0f::ff"},
				{12, "fe80::1"},
				{1, "1234:dead:beef:c0ff:ee:101::ff"},
			}

			for _, ip := range ips {
				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					pkt := packet(t, ip.hopLimit, ip.addr, []byte{})
					outPkt := testProg(t, test.getProgFunc(objs), pkt, test.passRC)
					assert.Equal(t, pkt, outPkt.Data(), "output package must be the same as input")
				})
			}
			if t.Failed() {
				statsPrint(t, objs.Exceed2goCounters)
			}
		})
	}
}

func TestEchoReply(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			objs := load(t)
			setMapIPs(t, objs.Exceed2goAddrs)

			for _, ip := range mapIPs() {
				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					pkt := packet(t, 64, ip.addr, []byte{})
					outPkt := testProg(t, test.getProgFunc(objs), pkt, test.redirectRC)
					outLayers := outPkt.Layers()
					require.Equal(t, 4, len(outLayers), "number of layers must be correct")

					ip6, ok := outLayers[1].(*layers.IPv6)
					if assert.True(t, ok, "must be IPv6") {
						assert.Equal(t, ip.addr, ip6.SrcIP.String(), "correct src address needed")
						assert.Equal(t, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
						assert.Equal(t, 16, int(ip6.Length), "correct length needed")
						assert.Equal(t, 6, int(ip6.Version), "correct version needed")
						assert.Equal(t, 64, int(ip6.HopLimit), "correct hop limit needed")
						assert.Equal(t, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
					}

					icmp6, ok := outLayers[2].(*layers.ICMPv6)
					if assert.True(t, ok, "must be ICMPv6") {
						assert.Equal(t, "EchoReply", icmp6.TypeCode.String())
						expectedChecksum := icmp6Checksum(t, ip.addr, "fd03::4", echoReplyTC, outPkt.Data()[58:])
						assert.Equal(t, expectedChecksum, icmp6.Checksum, "checksum must match")
					}
				})
			}
			if t.Failed() {
				statsPrint(t, objs.Exceed2goCounters)
			}
		})
	}
}

func TestChecksum(t *testing.T) {
	chksums := []struct {
		src     string
		dst     string
		chksum  int
		payload []string
	}{
		{
			"2a01:4f8:1c1c:86a3::ff:ee",
			"2a01:4f8:c010:a6ed::1",
			0xecff,
			[]string{
				"\x00\x00\x00\x00\x60\x06\x0b\xea\x00\x40\x3a\x01\x2a\x01\x04\xf8",
				"\xc0\x10\xa6\xed\x00\x00\x00\x00\x00\x00\x00\x01\x2a\x01\x04\xf8",
				"\x1c\x1c\x86\xa3\x00\x00\x00\x00\x00\xff\x00\xff\x80\x00\xdb\x22",
				"\x00\x09\x00\x0c\x2b\x4a\x13\x63\x00\x00\x00\x00\x36\x1e\x07\x00",
				"\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b",
				"\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b",
				"\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37",
			},
		},
		{
			"2a01:4f8:1c1c:86a3::ff:ee",
			"2a01:4f8:c010:a6ed::1",
			0xed2f,
			[]string{
				"\x00\x00\x00\x00\x60\x06\x0b\xea\x00\x10\x3a\x01\x2a\x01\x04\xf8",
				"\xc0\x10\xa6\xed\x00\x00\x00\x00\x00\x00\x00\x01\x2a\x01\x04\xf8",
				"\x1c\x1c\x86\xa3\x00\x00\x00\x00\x00\xff\x00\xff\x80\x00\x09\xe7",
				"\x00\x0a\x00\x05\x00\x01\x02\x03\x04\x05\x06\x07",
			},
		},
	}

	for idx, c := range chksums {
		chksum := icmp6Checksum(t, c.src, c.dst, timeExceededTC, []byte(strings.Join(c.payload, "")))
		assert.Equal(t, uint16(c.chksum), chksum, "must match: %d", idx)
	}
}
