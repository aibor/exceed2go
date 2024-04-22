// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"
	"net/netip"
)

// List of IPv6 addresses in the order they are supposed to appear in traces.
type HopList []netip.Addr

// ParseHopList translates a slice of IPv6 address strings into a slice of
// [netip.Addr]s. It returns an error if any of the strings can not be parsed
// as IPv6 address.
func ParseHopList(input []string) (HopList, error) {
	hopList := make(HopList, len(input))
	for idx, arg := range input {
		addr, err := ParseHop(arg)
		if err != nil {
			return nil, err
		}
		hopList[idx] = addr
	}
	return hopList, nil
}

// ParseHop parses a [netip.Addr] from an IPv6 address string. It returns an
// error if the strings can not be parsed as IPv6 address.
func ParseHop(input string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(input)
	if err != nil {
		return addr, fmt.Errorf("parse address: %s", input)
	}
	if !addr.Is6() {
		return addr, fmt.Errorf("not an IPv6 address: %s", input)
	}
	return addr, nil
}
