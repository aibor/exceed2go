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

type pinObj interface{
	IsPinned() bool
	Unpin() error
	Close() error
}

// MapIP contains an IPv6 addresses that is supposed to be returned for the
// given hop limit of incoming packets. HopLimit 0 is special and is the target
// address that should match the incoming destination address.
type MapIP struct {
	hopLimit int
	addr     string
}

// Load the BPF objects and return the object collection for further use, like
// attaching it to an interface.
func LoadAndPin() error {
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return fmt.Errorf("failed to create bpf pin dir: %w", err)
	}

	objs := bpfObjects{}
	err := loadBpfObjects(&objs, nil)
	if err != nil {
		return fmt.Errorf("failed to load objects: %w", err)
	}

	defer objs.Close()

	if err := objs.Exceed2go.Pin(programPinPath()); err != nil {
		return fmt.Errorf("failed to pin program: %w", err)
	}

	if err := objs.ExceedCounters.Pin(statsPinPath()); err != nil {
		return fmt.Errorf("failed to pin stats map: %w", err)
	}

	if err := objs.ExceedAddrs.Pin(configPinPath()); err != nil {
		return fmt.Errorf("failed to pin config map: %w", err)
	}

	return nil
}

// Cleanup unpins and closes all objects.
func Cleanup() {
	pinnedObjs := []func() (pinObj, error) {
		getPinnedLink,
		getPinnedProgram,
		getPinnedStatsMap,
		getPinnedConfigMap,
	}

	for _, objFunc := range pinnedObjs {
		obj, err := objFunc()
		if err != nil {
			continue
		}
		switch o := obj.(type) {
		case *ebpf.Program:
			if o == nil {
				continue
			}
		case *ebpf.Map:
			if o == nil {
				continue
			}
		default:
			continue
		}

		if obj.IsPinned() {
			_ = obj.Unpin()
		}
		_ = obj.Close()
	}

	_ = os.RemoveAll(pinPath)
}

// SetAddr puts the given address for the given hop number. Hop number 0 sets
// the target address to match.
func SetAddr(hop int, addr string) error {
	config, err := getPinnedConfigMap()
	if err != nil {
		return fmt.Errorf("failed to get config map: %w", err)
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("Cannot parse IP: %s", addr)
	}

	if err := config.(*ebpf.Map).Put(uint32(hop), []byte(ip)); err != nil {
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

	_, err = stats.(*ebpf.Map).BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)
	if err != nil {
		return lookupValues, fmt.Errorf("failed to lookup stats: %w", err)
	}

	return lookupValues, nil
}

// AttachProg attaches the XDP program to the interface with the given name. It
// returns a function that detaches and closes the objects and an error in case
// if failure.
func AttachProg(ifName string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("interface not found: %s: %w", ifName, err)
	}

	prog, err := getPinnedProgram()
	if err != nil {
		return fmt.Errorf("failed to get pinned program: %w", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program: prog.(*ebpf.Program),
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
	return path.Join(pinPath, "link")
}

func programPinPath() string {
	return path.Join(pinPath, "prog")
}

func statsPinPath() string {
	return path.Join(pinPath, "stats")
}

func configPinPath() string {
	return path.Join(pinPath, "config")
}

func getPinnedLink() (pinObj, error) {
	return ebpf.LoadPinnedProgram(linkPinPath(), nil)
}

func getPinnedProgram() (pinObj, error) {
	return ebpf.LoadPinnedProgram(programPinPath(), nil)
}

func getPinnedStatsMap() (pinObj, error) {
	return ebpf.LoadPinnedMap(statsPinPath(), nil)
}

func getPinnedConfigMap() (pinObj, error) {
	return ebpf.LoadPinnedMap(configPinPath(), nil)
}
