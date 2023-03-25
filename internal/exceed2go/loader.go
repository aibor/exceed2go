package exceed2go

import (
	"fmt"
	"net"
	"os"
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const pinPath = "/sys/fs/bpf/exceed2go"

// MapIP contains an IPv6 addresses that is supposed to be returned for the
// given hop limit of incoming packets.
type MapIP struct {
	hopLimit int
	addr     string
}

// Load the BPF objects and return the object collection for further use, like
// attaching it to an interface.
func Load() (*bpfObjects, error) {
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bpf pin dir: %w", err)
	}

	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load objects: %w", err)
	}

	return &objs, nil
}

func (o *bpfObjects) PinObjs() error {
	if err := o.Exceed2goCounters.Pin(statsPinPath()); err != nil {
		return fmt.Errorf("failed to pin stats map: %w", err)
	}

	if err := o.Exceed2goAddrs.Pin(configPinPath()); err != nil {
		return fmt.Errorf("failed to pin config map: %w", err)
	}

	return nil
}

// AttachProg attaches the XDP program to the interface with the given name. It
// pins the link in the directory for the program.
func (o *bpfObjects) AttachProg(ifName string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface not found: %s: %w", ifName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   o.Exceed2go,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to load XDP program: %w", err)
	}

	defer link.Close()

	if err := link.Pin(linkPinPath()); err != nil {
		return fmt.Errorf("failed to pin link: %w", err)
	}

	return nil
}

// Cleanup unpins and closes all objects.
func Cleanup() {
	_ = os.RemoveAll(pinPath)
}

// SetAddr puts the given address for the given hop number.
func SetAddr(hop int, addr string) error {
	config, err := getPinnedConfigMap()
	if err != nil {
		return fmt.Errorf("failed to get config map: %w", err)
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("Cannot parse IP: %s", addr)
	}

	if err := config.Put(uint32(hop), []byte(ip)); err != nil {
		return fmt.Errorf("map load error: %w", err)
	}

	return nil
}

// GetStats returns the current stats counter.
func GetStats() ([]uint32, error) {
	var (
		nextKey      uint32
		lookupKeys   = make([]uint32, 8)
		lookupValues = make([]uint32, 8)
	)

	stats, err := getPinnedStatsMap()
	if err != nil {
		return lookupValues, fmt.Errorf("failed to get stats map: %w", err)
	}

	_, err = stats.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)
	if err != nil {
		return lookupValues, fmt.Errorf("failed to lookup stats: %w", err)
	}

	return lookupValues, nil
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

func linkPinPath() string {
	return path.Join(pinPath, "xdp_link")
}

func statsPinPath() string {
	return path.Join(pinPath, "stats_map")
}

func configPinPath() string {
	return path.Join(pinPath, "config_map")
}

func getPinnedStatsMap() (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(statsPinPath(), nil)
}

func getPinnedConfigMap() (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(configPinPath(), nil)
}
