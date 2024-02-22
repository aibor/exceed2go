// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifinfo

import (
	"net"
)

// IfUpNameList returns a list of names of all interfaces that are up and not a
// loopback interface.
func IfUpNameList(ifaceList []net.Interface) []string {
	ifNameList := make([]string, 0)

	// fetch names for links that are up ant not loopback
	for _, iface := range ifaceList {
		if iface.Flags&(net.FlagUp|net.FlagLoopback) != net.FlagUp {
			continue
		}
		ifNameList = append(ifNameList, iface.Name)
	}

	return ifNameList
}
