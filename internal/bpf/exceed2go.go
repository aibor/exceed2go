// SPDX-FileCopyrightText: 2025 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bpf

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

//go:generate go tool bpf2go -target bpfel -cflags "-v -Wall -Werror -Wshadow -nostdinc" -no-strip Exceed2Go ../../bpf/exceed2go.c
//go:generate go tool stringer -type Exceed2GoCounterKey -trimprefix Exceed2GoCounterKeyCOUNTER_ -output exceed2go_counter_key_string.go

// SetAddrs provisions the addrs map with the given addresses.
func SetAddrs(spec *ebpf.CollectionSpec, addrs []netip.Addr) error {
	specs := &Exceed2GoSpecs{}
	if err := spec.Assign(specs); err != nil {
		return fmt.Errorf("assign specs: %w", err)
	}

	contents := []ebpf.MapKV{}
	for k, v := range addrs {
		contents = append(contents, ebpf.MapKV{
			// 0 is an invalid hop number, so it is left out.
			Key:   uint32(k) + 1, //nolint:gosec
			Value: v.As16(),
		})
	}

	specs.Exceed2goAddrs.MaxEntries = uint32(len(addrs)) + 1 //nolint:gosec
	specs.Exceed2goAddrs.Contents = contents

	return nil
}
