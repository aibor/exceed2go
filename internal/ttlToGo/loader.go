package ttlToGo

import (
	"fmt"
	"net"

	_ "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const AF_INET6 = 10

type CloseFunc = func() error

type MapIP struct {
	hopLimit int
	addr string
}

func Load() (*bpfObjects, error) {
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		return nil, fmt.Errorf("error loading objects: %w", err)
	}

	return &objs, nil
}

func (o *bpfObjects) SetAddr(idx int, addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("Cannot parse IP: %s", addr)
	}

	if err := o.TtlAddrs.Put(uint32(idx), []byte(ip)); err != nil {
		return fmt.Errorf("map load error: %w", err)
	}

	return nil
}

func (o *bpfObjects) GetStats() []uint32 {
	var (
		nextKey uint32
		lookupKeys   = make([]uint32, 8)
		lookupValues = make([]uint32, 8)
	)

	o.TtlCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

	return lookupValues
}

func (o *bpfObjects) AttachProg(ifName string) (CloseFunc, error) {
	closeFunc := func() error { return o.Close() }

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return closeFunc, fmt.Errorf("interface not found: %s: %w", ifName, err)
	}

	flags := nl.XDP_FLAGS_SKB_MODE
	if err := netlink.LinkSetXdpFdWithFlags(link, o.XdpTtltogo.FD(), flags); err != nil {
		return closeFunc, fmt.Errorf("failed to load XDP program: %w", err)
	}

	closeFunc = func() error {
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, flags); err != nil {
			return fmt.Errorf("error detaching from link (detach amnually with `ip link`: %w", err)
		}

		return o.Close()
	}

	return closeFunc, nil
}

func LinkUpNameList() []string {
	linkNameList := make([]string, 0)

	linkList, err := netlink.LinkList()
	if err != nil {
		return linkNameList
	}

	// fetch names for links that are up ant not loopback
	for _, link := range linkList {
		if  link.Attrs().Flags & (net.FlagUp | net.FlagLoopback) != net.FlagUp {
			continue
		}
		linkNameList = append(linkNameList, link.Attrs().Name)
	}

	return linkNameList
}

func IPv6AddrsList(ifName string) []string {
	ipv6AddrList := make([]string, 0)

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return ipv6AddrList
	}

	addrList, err := netlink.AddrList(link, AF_INET6)
	if err != nil {
		return ipv6AddrList
	}

	for _, addr := range addrList {
		if addr.IP.IsGlobalUnicast() {
			ipv6AddrList = append(ipv6AddrList, addr.IP.String())
		}
	}

	return ipv6AddrList
}
