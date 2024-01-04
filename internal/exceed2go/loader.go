package exceed2go

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/aibor/exceed2go/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// BPFFSDir is the bpffs sub directory containing all bpf pin files.
const BPFFSDir = "/sys/fs/bpf/exceed2go"

// PinFileName is the file name for a bpf object in [BPFFSDir].
type PinFileName string

// PinFileNames of the bpf objects used by the program.
const (
	PinFileNameXDPProg   PinFileName = "xdp_prog"
	PinFileNameXDPLink   PinFileName = "xdp_link"
	PinFileNameStatsMap  PinFileName = "stats_map"
	PinFileNameConfigMap PinFileName = "config_map"
)

type pinner interface {
	Pin(string) error
}

// BPFFSPath returns the absolute path for the given [PinFileName].
func BPFFSPath(path PinFileName) string {
	return filepath.Join(BPFFSDir, string(path))
}

// LoadAndPin loads the eBPF objects into the kernel and pins them to the bpffs.
//
// This is the initial action. If there are already loaded objects before, they
// are removed and so any state of them.
//
// Call [Remove] to unload the objects and clear the bpffs files.
func LoadAndPin() error {
	Remove()

	if err := os.MkdirAll(BPFFSPath(""), 0755); err != nil {
		return fmt.Errorf("create bpf pin dir: %v", err)
	}

	objs := bpf.Exceed2GoObjects{}
	err := bpf.LoadExceed2GoObjects(&objs, nil)
	defer objs.Exceed2GoPrograms.Close()
	if err != nil {
		Remove()
		return fmt.Errorf("load maps: %w", err)
	}

	pinners := map[pinner]PinFileName{
		objs.Exceed2go:         PinFileNameXDPProg,
		objs.Exceed2goCounters: PinFileNameStatsMap,
		objs.Exceed2goAddrs:    PinFileNameConfigMap,
	}

	for pinner, path := range pinners {
		if err := pinner.Pin(BPFFSPath(path)); err != nil {
			Remove()
			return fmt.Errorf("pin %s: %v", path, err)
		}
	}

	return nil
}

// AttachProg attaches the XDP program to the given [net.Interface].
//
// Am eBPF link is created to keep the eBPF program attached to the interface
// beyond the lifetime of the process.
func AttachProg(iface *net.Interface) error {
	prog, err := ebpf.LoadPinnedProgram(BPFFSPath(PinFileNameXDPProg), nil)
	if err != nil {
		return fmt.Errorf("load pinned program: %v", err)
	}
	defer prog.Close()

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("load XDP program: %v", err)
	}
	defer link.Close()

	if err := link.Pin(BPFFSPath(PinFileNameXDPLink)); err != nil {
		return fmt.Errorf("pin link: %v", err)
	}

	return nil
}

// Remove unpins and closes all objects.
func Remove() {
	_ = os.RemoveAll(BPFFSPath(""))
}

// SetAddrs puts the given addresses for the given hop numbers (indexes).
//
// It overrides the whole eBPF map, so no incremental changes possible.
func SetAddrs(hops HopList) error {
	config, err := ebpf.LoadPinnedMap(BPFFSPath(PinFileNameConfigMap), nil)
	if err != nil {
		return fmt.Errorf("get config map: %v", err)
	}
	defer config.Close()

	maxEntries := int(config.MaxEntries())
	if len(hops) >= maxEntries {
		return fmt.Errorf("too many hops %d, max %d", len(hops), maxEntries-1)
	}
	keys := make([]uint32, maxEntries)
	values := make([][16]byte, maxEntries)

	for idx, addr := range hops {
		// 0 is an invalid hop number, so it is left out.
		keys[idx] = uint32(idx + 1)
		values[idx] = addr.As16()
	}

	if _, err := config.BatchUpdate(keys, values, nil); err != nil {
		return fmt.Errorf("load error: %v", err)
	}

	return nil
}

// GetAddrs returns the content of the eBPF map.
func GetAddrs() (HopList, error) {
	var output = make(HopList, 0)

	config, err := ebpf.LoadPinnedMap(BPFFSPath(PinFileNameConfigMap), nil)
	if err != nil {
		return output, fmt.Errorf("get config map: %v", err)
	}
	defer config.Close()

	var (
		cursor       ebpf.BatchCursor
		lookupKeys   = make([]uint32, config.MaxEntries())
		lookupValues = make([][16]byte, config.MaxEntries())
	)

	_, err = config.BatchLookup(&cursor, lookupKeys, lookupValues, nil)
	if err != nil {
		return output, fmt.Errorf("lookup stats: %v", err)
	}

	for idx := range lookupKeys {
		// 0 is an invalid hop number, so it is left out.
		if idx == 0 {
			continue
		}
		addr := netip.AddrFrom16(lookupValues[idx])
		if addr.IsUnspecified() {
			break
		}
		output = append(output, addr)
	}

	return output, nil
}

// Stat represents a single counter value from the eBPF counters map.
type Stat struct {
	Name  string
	Count int
}

// Stats is a list of [Stat]s.
type Stats []Stat

// GetStats returns the current stats counters.
func GetStats() (Stats, error) {
	var output = make(Stats, 0)

	stats, err := ebpf.LoadPinnedMap(BPFFSPath(PinFileNameStatsMap), nil)
	if err != nil {
		return output, fmt.Errorf("get stats map: %v", err)
	}
	defer stats.Close()

	var (
		cursor       ebpf.BatchCursor
		lookupKeys   = make([]uint32, stats.MaxEntries())
		lookupValues = make([]uint32, stats.MaxEntries())
	)

	_, err = stats.BatchLookup(&cursor, lookupKeys, lookupValues, nil)
	if err != nil {
		return output, fmt.Errorf("lookup stats: %v", err)
	}

	for idx, key := range lookupKeys {
		output = append(output, Stat{
			Name:  bpf.Exceed2GoCounterKey(key).String(),
			Count: int(lookupValues[idx]),
		})
	}
	return output, nil
}
