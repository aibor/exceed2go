// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/aibor/exceed2go/internal/bpf"
	"github.com/cilium/ebpf"
)

// Names of bpf maps. Must match the actual symbols of the maps.
const (
	statsMapName = "exceed2go_counters"
	addrsMapName = "exceed2go_addrs"
)

// bpffsDir is the bpffs sub directory containing all bpf pin files.
const bpffsDir = "/sys/fs/bpf/exceed2go"

func ifaceDir(ifaceIndex int) string {
	return filepath.Join(bpffsDir, strconv.Itoa(ifaceIndex))
}

func ifacePath(ifaceIndex int, name string) string {
	return filepath.Join(ifaceDir(ifaceIndex), name)
}

// KnownIface returns if exceed2go is attached to the interface.
func KnownIface(ifaceIndex int) bool {
	_, err := os.Stat(ifaceDir(ifaceIndex))

	return !os.IsNotExist(err)
}

// RemoveAll unpins and closes all objects.
func RemoveAll() {
	_ = os.RemoveAll(bpffsDir)
}

// RemoveIface unpins and closes all objects for the given iface index.
func RemoveIface(ifaceIndex int) {
	_ = os.RemoveAll(ifaceDir(ifaceIndex))
}

// load loads the eBPF objects into the kernel and pins them to the bpffs. The
// given hoplist is written to the according map.
//
// This is the initial action. If there are already loaded objects before, they
// are removed and so any state of them.
//
// Call [Remove] to unload the objects and clear the bpffs files.
func load(pinDir string, hops HopList) (*bpf.Exceed2GoObjects, error) {
	spec, err := bpf.LoadExceed2Go()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	err = bpf.SetAddrs(spec, hops)
	if err != nil {
		return nil, fmt.Errorf("set addresses: %w", err)
	}

	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	objs := &bpf.Exceed2GoObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinDir,
		},
	}

	err = spec.LoadAndAssign(objs, opts)
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}

	return objs, nil
}

// getPinnedMap loads the pinned [ebpf.Map] with the given name.
func getPinnedMap(ifaceIndex int, name string) (*ebpf.Map, error) {
	path := ifacePath(ifaceIndex, name)

	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("get map %d/%s: %w", ifaceIndex, name, err)
	}

	return m, nil
}
