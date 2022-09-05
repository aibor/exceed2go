package exceed2go

import (
	"fmt"
	"net"

	_ "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const AF_INET6 = 10

type CloseFunc = func() error

type MapIP struct {
	hopLimit int
	addr     string
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

	if err := o.ExceedAddrs.Put(uint32(idx), []byte(ip)); err != nil {
		return fmt.Errorf("map load error: %w", err)
	}

	return nil
}

func (o *bpfObjects) GetStats() []uint32 {
	var (
		nextKey      uint32
		lookupKeys   = make([]uint32, 8)
		lookupValues = make([]uint32, 8)
	)

	o.ExceedCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

	return lookupValues
}

func (o *bpfObjects) AttachProg(ifName string) (CloseFunc, error) {
	closeFunc := func() error { return o.Close() }

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return closeFunc, fmt.Errorf("interface not found: %s: %w", ifName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program: o.Exceed2go,
		Interface: iface.Index,
	})
	if err != nil {
		return closeFunc, fmt.Errorf("failed to load XDP program: %w", err)
	}

	closeFunc = func() error {
		if link.Close(); err != nil {
			return fmt.Errorf("error detaching from link (detach amnually with `ip link`: %w", err)
		}

		return o.Close()
	}

	return closeFunc, nil
}

func IfUpNameList() []string {
	ifNameList := make([]string, 0)

	ifList, err := net.Interfaces()
	if err != nil {
		return ifNameList
	}

	// fetch names for links that are up ant not loopback
	for _, iface := range ifList {
		if iface.Flags&(net.FlagUp|net.FlagLoopback) != net.FlagUp {
			continue
		}
		ifNameList = append(ifNameList, iface.Name)
	}

	return ifNameList
}

func IPv6AddrsList(ifName string) []string {
	ipv6AddrList := make([]string, 0)

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return ipv6AddrList
	}

	addrList, err := iface.Addrs()
	if err != nil {
		return ipv6AddrList
	}

	for _, addr := range addrList {
		ip := net.ParseIP(addr.String())
		if ip.IsGlobalUnicast() {
			ipv6AddrList = append(ipv6AddrList, addr.String())
		}
	}

	return ipv6AddrList
}
