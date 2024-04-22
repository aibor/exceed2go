// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

func ifaceCompletion(_ *cobra.Command, _ []string, _ string) (
	[]string, cobra.ShellCompDirective,
) {
	comps := make([]string, 0)
	flags := cobra.ShellCompDirectiveNoFileComp

	ifaceList, err := net.Interfaces()
	if err != nil {
		return comps, flags
	}

	comps = ifaceUpNameList(ifaceList)

	return comps, flags
}

func ifaceByName(name string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface by name: %s: %v", name, err)
	}

	return iface, nil
}

// ifaceUpNameList returns a list of names of all interfaces that are up and not a
// loopback interface.
func ifaceUpNameList(ifaceList []net.Interface) []string {
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
