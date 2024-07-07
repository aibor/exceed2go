// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bpf_test

import (
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
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

const (
	ipv6MinMTU = 1280
	senderAddr = "fd03::4"
	targetAddr = "fd01::ff"
)

var (
	loadFailed atomic.Bool

	mapIPs = []MapIP{
		{1, "fd01::bb"},
		{2, "fd01::cc"},
		{3, "fd01::dd"},
		{4, "fd01::ee"},
		{5, targetAddr},
	}

	ethIPv6In = layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC:       net.HardwareAddr{0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ethIPv6Out = layers.Ethernet{
		SrcMAC:       ethIPv6In.DstMAC,
		DstMAC:       ethIPv6In.SrcMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	icmp6echo = layers.ICMPv6Echo{
		Identifier: 1,
		SeqNumber:  1,
	}
)

type MapIP struct {
	hopLimit int
	addr     string
}

func addEth(
	tb testing.TB,
	layer []gopacket.SerializableLayer,
	eth layers.Ethernet,
) []gopacket.SerializableLayer {
	tb.Helper()

	return slices.Insert(layer, 0, gopacket.SerializableLayer(&eth))
}

func serialize(tb testing.TB, layer ...gopacket.SerializableLayer) []byte {
	tb.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var networkLayer gopacket.NetworkLayer
	for _, l := range layer {
		if networkLayer == nil {
			if nw, ok := l.(gopacket.NetworkLayer); ok {
				networkLayer = nw
			}
		}

		if icmp6, ok := l.(*layers.ICMPv6); ok {
			require.NotNil(tb, networkLayer, "missing network layer")
			err := icmp6.SetNetworkLayerForChecksum(networkLayer)
			require.NoError(tb, err, "must set layer for checksum")
		}
	}

	err := gopacket.SerializeLayers(buf, opts, layer...)
	require.NoError(tb, err, "must serialize packet")

	return buf.Bytes()
}

func deserialize(tb testing.TB, data []byte, noEth bool) gopacket.Packet {
	tb.Helper()

	lt := layers.LayerTypeEthernet
	if noEth {
		lt = layers.LayerTypeIPv6
	}

	pkt := gopacket.NewPacket(data, lt, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		tb.Fatalf("error decoding packet: %v", pkt.ErrorLayer())
	}

	return pkt
}

func load(tb testing.TB) *bpf.Exceed2GoObjects {
	tb.Helper()

	if loadFailed.Load() {
		tb.Fatal("Fail due to previous load errors")
	}

	objs := &bpf.Exceed2GoObjects{}
	if err := bpf.LoadExceed2GoObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			tb.Logf("verifier log:\n %s", strings.Join(ve.Log, "\n"))
		}

		loadFailed.Store(true)
		tb.Fatalf("error loading objects: %v", err)
	}

	tb.Cleanup(func() {
		_ = objs.Close()
	})

	return objs
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

	return deserialize(tb, opts.DataOut, p.noEth)
}

func (p *progTest) statsPrint(tb testing.TB) {
	tb.Helper()

	var (
		stats        = p.objs.Exceed2goCounters
		cursor       ebpf.MapBatchCursor
		lookupKeys   = make([]uint32, stats.MaxEntries())
		lookupValues = make([]uint32, stats.MaxEntries())
	)

	_, _ = stats.BatchLookup(&cursor, lookupKeys, lookupValues, nil)

	for idx, key := range lookupKeys {
		tb.Logf("%-25s  %d", bpf.Exceed2GoCounterKey(key), lookupValues[idx])
	}
}

func (p *progTest) setup(tb testing.TB) {
	tb.Helper()

	if p.noEth {
		tb.Skip("support for layer 3 type missing")
	}

	p.objs = load(tb)

	for _, ip := range mapIPs {
		err := p.objs.Exceed2goAddrs.Put(uint32(ip.hopLimit), net.ParseIP(ip.addr))
		if err != nil {
			tb.Fatalf("map load error: %v", err)
		}
	}
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

			for _, ip := range mapIPs[:len(mapIPs)-1] {
				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					inLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(senderAddr),
							DstIP:      net.ParseIP(targetAddr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   uint8(ip.hopLimit),
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeEchoRequest,
								0,
							),
						},
						&icmp6echo,
						gopacket.Payload{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4},
					}

					outLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(ip.addr),
							DstIP:      net.ParseIP(senderAddr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   64,
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeTimeExceeded,
								layers.ICMPv6CodeHopLimitExceeded,
							),
						},
						gopacket.Payload{0x0, 0x0, 0x0, 0x0},
						gopacket.Payload(serialize(t, inLayers...)),
					}

					if !test.noEth {
						inLayers = addEth(t, inLayers, ethIPv6In)
						outLayers = addEth(t, outLayers, ethIPv6Out)
					}

					expectedPkt := deserialize(t, serialize(t, outLayers...), test.noEth)
					actualPkt := test.run(t, serialize(t, inLayers...), test.redirectRC)

					assert.Equal(t, expectedPkt.String(), actualPkt.String())
				})
			}

			if t.Failed() {
				test.statsPrint(t)
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
				len       int
			}{
				{false, 8},
				{false, 1182},
				{false, 1183},
				{false, 1184},
				{true, 1185},
				{true, 1186},
				{true, 1187},
				{true, 1400},
			}

			entry := mapIPs[0]

			for _, payload := range payloads {
				t.Run(fmt.Sprintf("payload size %d", payload.len), func(t *testing.T) {
					inLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(senderAddr),
							DstIP:      net.ParseIP(targetAddr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   uint8(entry.hopLimit),
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeEchoRequest,
								0,
							),
						},
						&icmp6echo,
						make(gopacket.Payload, payload.len),
					}

					respPacket := serialize(t, inLayers...)
					// The eBPF program aligns the packet to 4 byte.
					respPacket = respPacket[:len(respPacket) & ^3]
					// The ICMPv6 packets must not exceed IPv6 minimum MTU.
					if len(respPacket) > ipv6MinMTU-48 {
						respPacket = respPacket[:ipv6MinMTU-48]
					}

					outLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(entry.addr),
							DstIP:      net.ParseIP(senderAddr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   64,
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeTimeExceeded,
								layers.ICMPv6CodeHopLimitExceeded,
							),
						},
						gopacket.Payload{0x0, 0x0, 0x0, 0x0},
						gopacket.Payload(respPacket),
					}

					maxLen := ipv6MinMTU
					if !test.noEth {
						maxLen += 14
						inLayers = addEth(t, inLayers, ethIPv6In)
						outLayers = addEth(t, outLayers, ethIPv6Out)
					}

					expectedPkt := deserialize(t, serialize(t, outLayers...), test.noEth)
					actualPkt := test.run(t, serialize(t, inLayers...), test.redirectRC)
					actualLen := len(actualPkt.Data())

					assert.Equal(t, expectedPkt.String(), actualPkt.String())

					if payload.truncated {
						assert.Equal(t, maxLen, actualLen)
					} else {
						assert.LessOrEqual(t, actualLen, maxLen, "IPv6 minimum MTU")
					}
				})
			}

			if t.Failed() {
				test.statsPrint(t)
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
					inLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(senderAddr),
							DstIP:      net.ParseIP(ip.addr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   uint8(ip.hopLimit),
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeEchoRequest,
								0,
							),
						},
						&icmp6echo,
						gopacket.Payload{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4},
					}

					if !test.noEth {
						inLayers = addEth(t, inLayers, ethIPv6In)
					}

					expectedPkt := deserialize(t, serialize(t, inLayers...), test.noEth)
					actualPkt := test.run(t, serialize(t, inLayers...), test.passRC)

					assert.Equal(t, expectedPkt.String(), actualPkt.String())
				})
			}

			if t.Failed() {
				test.statsPrint(t)
			}
		})
	}
}

func TestEchoReply(t *testing.T) {
	for progType, test := range progTests {
		t.Run(progType, func(t *testing.T) {
			test.setup(t)

			for _, ip := range mapIPs {
				t.Run(fmt.Sprintf("hop %d", ip.hopLimit), func(t *testing.T) {
					inLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(senderAddr),
							DstIP:      net.ParseIP(ip.addr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   64,
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeEchoRequest,
								0,
							),
						},
						&icmp6echo,
						gopacket.Payload{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4},
					}

					outLayers := []gopacket.SerializableLayer{
						&layers.IPv6{
							Version:    6,
							SrcIP:      net.ParseIP(ip.addr),
							DstIP:      net.ParseIP(senderAddr),
							NextHeader: layers.IPProtocolICMPv6,
							HopLimit:   64,
						},
						&layers.ICMPv6{
							TypeCode: layers.CreateICMPv6TypeCode(
								layers.ICMPv6TypeEchoReply,
								0,
							),
						},
						&icmp6echo,
						gopacket.Payload{0x0, 0x0, 0x0, 0x0, 1, 2, 3, 4},
					}

					if !test.noEth {
						inLayers = addEth(t, inLayers, ethIPv6In)
						outLayers = addEth(t, outLayers, ethIPv6Out)
					}

					expectedPkt := deserialize(t, serialize(t, outLayers...), test.noEth)
					actualPkt := test.run(t, serialize(t, inLayers...), test.redirectRC)

					assert.Equal(t, expectedPkt.String(), actualPkt.String())
				})
			}

			if t.Failed() {
				test.statsPrint(t)
			}
		})
	}
}
