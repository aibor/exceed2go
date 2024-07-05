// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/aibor/exceed2go/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	LoadFailed     atomic.Bool
	timeExceededTC = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, 0)
	echoReplyTC    = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)
)

func handleLoadError(tb testing.TB, err error) {
	tb.Helper()

	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		tb.Logf("verifier log:\n %s", strings.Join(ve.Log, "\n"))
	}

	LoadFailed.Store(true)
	tb.Fatalf("error loading objects: %v", err)
}

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

func packet(tb testing.TB, hopLimit int, dstAddr string, payload []byte, noEth bool) []byte {
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

	var layer []gopacket.SerializableLayer
	if !noEth {
		layer = append(layer, &eth)
	}

	layer = append(layer, &ipv6, &icmp6, &icmp6echo, &pload)
	err = gopacket.SerializeLayers(buf, opts, layer...)
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
	if err := bpf.LoadExceed2GoObjects(objs, nil); err != nil {
		handleLoadError(tb, err)
	}

	tb.Cleanup(func() {
		if objs != nil {
			objs.Close()
		}
	})

	return objs
}

func setAddr(tb testing.TB, config *ebpf.Map, idx int, addr string) {
	tb.Helper()

	if err := config.Put(uint32(idx), netip.MustParseAddr(addr).AsSlice()); err != nil {
		tb.Fatalf("map load error: %v", err)
	}
}

func statsPrint(tb testing.TB, stats *ebpf.Map) {
	tb.Helper()

	var (
		cursor       ebpf.MapBatchCursor
		lookupKeys   = make([]uint32, stats.MaxEntries())
		lookupValues = make([]uint32, stats.MaxEntries())
	)

	_, _ = stats.BatchLookup(&cursor, lookupKeys, lookupValues, nil)

	for idx, key := range lookupKeys {
		tb.Logf("%-25s  %d", bpf.Exceed2GoCounterKey(key), lookupValues[idx])
	}
}

type progTest struct {
	getProgFunc func(*bpf.Exceed2GoObjects) *ebpf.Program
	getRunOpts  func() *ebpf.RunOptions
	redirectRC  uint32
	passRC      uint32
	objs        *bpf.Exceed2GoObjects
	noEth       bool
}

func (p *progTest) run(tb testing.TB, pkt []byte, rc uint32) gopacket.Packet {
	tb.Helper()

	opts := p.getRunOpts()
	opts.Data = pkt
	opts.Repeat = 1
	opts.DataOut = make([]byte, len(pkt)+258)

	prog := p.getProgFunc(p.objs)
	ret, err := prog.Run(opts)
	require.NoError(tb, err, "program must run without error")
	assert.Equal(tb, rc, ret, "return code should be correct")

	lt := layers.LayerTypeEthernet
	if p.noEth {
		lt = layers.LayerTypeIPv6
	}

	return gopacket.NewPacket(opts.DataOut, lt, gopacket.Default)
}

func (p *progTest) layerIPv6() int {
	l := 1
	if p.noEth {
		l = 0
	}

	return l
}

func (p *progTest) setup(tb testing.TB) {
	tb.Helper()

	if p.noEth {
		tb.Skip("support for layer 3 type missing")
	}

	p.objs = load(tb)
	setMapIPs(tb, p.objs.Exceed2goAddrs)
}

var progTests = map[string]progTest{
	"xdp_l2": {
		getProgFunc: func(objs *bpf.Exceed2GoObjects) *ebpf.Program {
			return objs.Exceed2goXdpL2
		},
		getRunOpts: func() *ebpf.RunOptions {
			return &ebpf.RunOptions{}
		},
		redirectRC: 3,
		passRC:     2,
		noEth:      false,
	},
	"tc_l2": {
		getProgFunc: func(objs *bpf.Exceed2GoObjects) *ebpf.Program {
			return objs.Exceed2goTcL2
		},
		getRunOpts: func() *ebpf.RunOptions {
			return &ebpf.RunOptions{
				Context: bpf.SkBuff{
					// bpf_skb_adjust_room requires skb->protocol set. pbf prog
					// run does not allow the field to be set and it always
					// retrieves it from the interface. Because of this use an
					// actual interface so the value is properly set.
					Ifindex: 1,
				},
			}
		},
		redirectRC: 7,
		passRC:     math.MaxUint32,
		noEth:      false,
	},
	"tc_l3": {
		getProgFunc: func(objs *bpf.Exceed2GoObjects) *ebpf.Program {
			return objs.Exceed2goTcL3
		},
		getRunOpts: func() *ebpf.RunOptions {
			return &ebpf.RunOptions{
				Context: bpf.SkBuff{
					Ifindex: 1,
				},
			}
		},
		redirectRC: 7,
		passRC:     math.MaxUint32,
		noEth:      true,
	},
}

func TestTTL(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			test.setup(t)

			for idx, ip := range mapIPs() {
				if idx == 4 {
					continue
				}

				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					pkt := packet(t, ip.hopLimit, mapIPs()[4].addr, []byte{}, test.noEth)
					outPkt := test.run(t, pkt, test.redirectRC)

					outLayers := outPkt.Layers()
					if !assert.Len(t, outLayers, test.layerIPv6()+3, "number of layers must be correct") {
						t.Log(outPkt.String())
						t.FailNow()
					}

					ip6, ok := outLayers[test.layerIPv6()].(*layers.IPv6)
					if assert.True(t, ok, "must be IPv6") {
						assert.Equal(t, ip.addr, ip6.SrcIP.String(), "correct src address needed")
						assert.Equal(t, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
						assert.Equal(t, 64, int(ip6.Length), "correct length needed")
						assert.Equal(t, 6, int(ip6.Version), "correct version needed")
						assert.Equal(t, 64, int(ip6.HopLimit), "correct hop limit needed")
						assert.Equal(t, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
					}

					icmp6, ok := outLayers[test.layerIPv6()+1].(*layers.ICMPv6)
					if assert.True(t, ok, "must be ICMPv6") {
						assert.Equal(t, "TimeExceeded(HopLimitExceeded)", icmp6.TypeCode.String())

						csumData := outPkt.Data()[44+14*test.layerIPv6():]
						expectedChecksum := icmp6Checksum(t, ip.addr, "fd03::4", timeExceededTC, csumData)
						assert.Equal(t, expectedChecksum, icmp6.Checksum, "checksum must match")
					}
				})
			}

			if t.Failed() {
				statsPrint(t, test.objs.Exceed2goCounters)
			}
		})
	}
}

func TestTTLMaxSize(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			test.setup(t)

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

					payloadSize := (len(payload.payload) & ^3) + 56
					if payload.truncated {
						payloadSize = 1240
					}

					pktSize := payloadSize + 40 + 14*test.layerIPv6()

					pkt := packet(t, 1, mapIPs()[4].addr, payload.payload, test.noEth)
					outPkt := test.run(t, pkt, test.redirectRC)
					assert.Len(t, outPkt.Data(), pktSize, "out package must have correct length")

					outLayers := outPkt.Layers()
					if !assert.Len(t, outLayers, test.layerIPv6()+3, "number of layers must be correct") {
						t.Log(outPkt.String())
						t.FailNow()
					}

					ip6, ok := outLayers[test.layerIPv6()].(*layers.IPv6)
					if assert.True(t, ok, "must be IPv6") {
						assert.Equal(t, ip.addr, ip6.SrcIP.String(), "correct src address needed")
						assert.Equal(t, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
						assert.Equal(t, payloadSize, int(ip6.Length), "correct length needed")
						assert.Equal(t, 6, int(ip6.Version), "correct version needed")
						assert.Equal(t, 64, int(ip6.HopLimit), "correct hop limit needed")
						assert.Equal(t, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
					}

					icmp6, ok := outLayers[test.layerIPv6()+1].(*layers.ICMPv6)
					if assert.True(t, ok, "must be ICMPv6") {
						assert.Equal(t, "TimeExceeded(HopLimitExceeded)", icmp6.TypeCode.String())

						csumData := outPkt.Data()[44+14*test.layerIPv6():]
						expectedChecksum := icmp6Checksum(t, ip.addr, "fd03::4", timeExceededTC, csumData)
						assert.Equal(t, expectedChecksum, icmp6.Checksum, "checksum must match")
					}
				})
			}

			if t.Failed() {
				statsPrint(t, test.objs.Exceed2goCounters)
			}
		})
	}
}

func TestNoMatch(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			test.setup(t)

			ips := []MapIP{
				{42, "fd0f::ff"},
				{12, "fe80::1"},
				{1, "1234:dead:beef:c0ff:ee:101::ff"},
			}

			for _, ip := range ips {
				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					pkt := packet(t, ip.hopLimit, ip.addr, []byte{}, test.noEth)
					outPkt := test.run(t, pkt, test.passRC)
					assert.Equal(t, pkt, outPkt.Data(), "output package must be the same as input")
				})
			}

			if t.Failed() {
				statsPrint(t, test.objs.Exceed2goCounters)
			}
		})
	}
}

func TestEchoReply(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			test.setup(t)

			for _, ip := range mapIPs() {
				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					pkt := packet(t, 64, ip.addr, []byte{}, test.noEth)
					outPkt := test.run(t, pkt, test.redirectRC)

					outLayers := outPkt.Layers()
					if !assert.Len(t, outLayers, test.layerIPv6()+3, "number of layers must be correct") {
						t.Log(outPkt.String())
						t.FailNow()
					}

					ip6, ok := outLayers[test.layerIPv6()].(*layers.IPv6)
					if assert.True(t, ok, "must be IPv6") {
						assert.Equal(t, ip.addr, ip6.SrcIP.String(), "correct src address needed")
						assert.Equal(t, "fd03::4", ip6.DstIP.String(), "correct dst address needed")
						assert.Equal(t, 16, int(ip6.Length), "correct length needed")
						assert.Equal(t, 6, int(ip6.Version), "correct version needed")
						assert.Equal(t, 64, int(ip6.HopLimit), "correct hop limit needed")
						assert.Equal(t, layers.IPProtocolICMPv6, ip6.NextHeader, "correct next header needed")
					}

					icmp6, ok := outLayers[test.layerIPv6()+1].(*layers.ICMPv6)
					if assert.True(t, ok, "must be ICMPv6") {
						assert.Equal(t, "EchoReply", icmp6.TypeCode.String())

						csumData := outPkt.Data()[44+14*test.layerIPv6():]
						expectedChecksum := icmp6Checksum(t, ip.addr, "fd03::4", echoReplyTC, csumData)
						assert.Equal(t, expectedChecksum, icmp6.Checksum, "checksum must match")
					}
				})
			}

			if t.Failed() {
				statsPrint(t, test.objs.Exceed2goCounters)
			}
		})
	}
}

func TestChecksum(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		dst     string
		payload []byte
		chksum  int
	}{
		{
			name: "icmp echo request long",
			src:  "2a01:4f8:1c1c:86a3::ff:ee",
			dst:  "2a01:4f8:c010:a6ed::1",
			payload: []byte{
				0x00, 0x00, 0x00, 0x00, 0x60, 0x06, 0x0b, 0xea, 0x00, 0x40, 0x3a, 0x01, 0x2a, 0x01, 0x04, 0xf8,
				0xc0, 0x10, 0xa6, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x01, 0x04, 0xf8,
				0x1c, 0x1c, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x80, 0x00, 0xdb, 0x22,
				0x00, 0x09, 0x00, 0x0c, 0x2b, 0x4a, 0x13, 0x63, 0x00, 0x00, 0x00, 0x00, 0x36, 0x1e, 0x07, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
				0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			},
			chksum: 0xecff,
		},
		{
			name: "icmp echo request short",
			src:  "2a01:4f8:1c1c:86a3::ff:ee",
			dst:  "2a01:4f8:c010:a6ed::1",
			payload: []byte{
				0x00, 0x00, 0x00, 0x00, 0x60, 0x06, 0x0b, 0xea, 0x00, 0x10, 0x3a, 0x01, 0x2a, 0x01, 0x04, 0xf8,
				0xc0, 0x10, 0xa6, 0xed, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x01, 0x04, 0xf8,
				0x1c, 0x1c, 0x86, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x80, 0x00, 0x09, 0xe7,
				0x00, 0x0a, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			},
			chksum: 0xed2f,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chksum := icmp6Checksum(t, tt.src, tt.dst, timeExceededTC, tt.payload)
			assert.Equal(t, uint16(tt.chksum), chksum)
		})
	}
}
