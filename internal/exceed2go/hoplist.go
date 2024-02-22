// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package exceed2go

import (
	"fmt"
	"net/netip"
)

type HopList []netip.Addr

func ParseHopList(input []string) (HopList, error) {
	hopList := make(HopList, len(input))
	for idx, arg := range input {
		addr, err := netip.ParseAddr(arg)
		if err != nil {
			return hopList, fmt.Errorf("parse address: %s", arg)
		}
		if !addr.Is6() {
			return hopList, fmt.Errorf("not an IPv6 address: %s", arg)
		}
		hopList[idx] = addr
	}
	return hopList, nil
}
