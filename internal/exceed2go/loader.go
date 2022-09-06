package exceed2go

import (
	"fmt"
	"net"

	_ "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// CloseFunc is supposed to detach and cleanup bpf objects. is supposed to be
// called once the resources are not used anymore. It returns an error if
// detaching or closing fails.
type CloseFunc = func() error

// MapIP contains an IPv6 addresses that is supposed to be returned for the
// given hop limit of incoming packets. HopLimit 0 is special and is the target
// address that should match the incoming destination address.
type MapIP struct {
	hopLimit int
	addr     string
}

// Load the BPF objects and return the object collection for further use, like
// attaching it to an interface.
func Load() (*bpfObjects, error) {
	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		return nil, fmt.Errorf("error loading objects: %w", err)
	}

	return &objs, nil
}

// SetAddr puts the given address for the given hop number. Hop number 0 sets
// the target address to match.
func (o *bpfObjects) SetAddr(hop int, addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("Cannot parse IP: %s", addr)
	}

	if err := o.ExceedAddrs.Put(uint32(hop), []byte(ip)); err != nil {
		return fmt.Errorf("map load error: %w", err)
	}

	return nil
}

// GetStats returns the current stats counter.
func (o *bpfObjects) GetStats() []uint32 {
	var (
		nextKey      uint32
		lookupKeys   = make([]uint32, 8)
		lookupValues = make([]uint32, 8)
	)

	// TODO: error handling
	_, _ = o.ExceedCounters.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)

	return lookupValues
}

// AttachProg attaches the XDP program to the interface with the given name. It
// returns a function that detaches and closes the objects and an error in case
// if failure.
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
			return fmt.Errorf("error detaching from link (detach manually with `ip link`: %w", err)
		}

		return o.Close()
	}

	return closeFunc, nil
}

// IfUpNameList returns a list of names of all interfaces that are up and not a
// loopback interface.
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

// IPv6AddrsList fetches a list of all globally routable unicast IPv6 addresses
// of the interface identified by the given name.
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
