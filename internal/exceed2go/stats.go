// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"

	"github.com/aibor/exceed2go/internal/bpf"
	"github.com/cilium/ebpf"
)

// Stat represents a single counter value from the eBPF counters map.
type Stat struct {
	Name  string
	Count int
}

// Stats is a list of [Stat]s.
type Stats []Stat

// ReadStats returns the current stats counters.
func ReadStats(ifaceIndex int) (Stats, error) {
	statsMap, err := getPinnedMap(ifaceIndex, statsMapName)
	if err != nil {
		return nil, err
	}
	defer statsMap.Close()

	return readStats(statsMap)
}

func readStats(statsMap *ebpf.Map) (Stats, error) {
	var (
		cursor       ebpf.MapBatchCursor
		lookupKeys   = make([]uint32, statsMap.MaxEntries())
		lookupValues = make([]uint32, statsMap.MaxEntries())
		output       = make(Stats, statsMap.MaxEntries())
	)

	_, err := statsMap.BatchLookup(&cursor, lookupKeys, lookupValues, nil)
	if err != nil {
		return nil, fmt.Errorf("lookup stats: %v", err)
	}

	for idx, key := range lookupKeys {
		output[idx] = Stat{
			Name:  bpf.Exceed2GoCounterKey(key).String(),
			Count: int(lookupValues[idx]),
		}
	}

	return output, nil
}
