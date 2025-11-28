// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// ReadAddrs reads the currently configured addresses from the given addresses
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
		return output, fmt.Errorf("lookup stats: %w", err)
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
