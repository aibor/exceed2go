// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// GetAddrs reads the currently configured addresses from the given addresses
// map.
func ReadAddrs(ifaceIndex int) (HopList, error) {
	addrsMap, err := getPinnedMap(ifaceIndex, "exceed2go_addrs")
	if err != nil {
		return nil, err
	}
	defer addrsMap.Close() //nolint:errcheck

	return readAddrs(addrsMap)
}

func readAddrs(addrsMap *ebpf.Map) (HopList, error) {
	var (
		cursor       ebpf.MapBatchCursor
		lookupKeys   = make([]uint32, addrsMap.MaxEntries())
		lookupValues = make([][16]byte, addrsMap.MaxEntries())
		output       = make(HopList, 0)
	)

	_, err := addrsMap.BatchLookup(&cursor, lookupKeys, lookupValues, nil)
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

func writeAddrs(addrsMap *ebpf.Map, hops HopList) error {
	maxEntries := int(addrsMap.MaxEntries())
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

	if _, err := addrsMap.BatchUpdate(keys, values, nil); err != nil {
		return fmt.Errorf("load error: %v", err)
	}

	return nil
}
