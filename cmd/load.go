// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/aibor/exceed2go/internal/ifinfo"
)

func loadCmd() *cobra.Command {
	var (
		tc         bool
		ifaceNames []string
	)

	cmd := &cobra.Command{
		Use:   "load [flags...] HOP_ADDRESS ...",
		Short: "Load and configure the program",
		Long: `Attach the eBPF program to one or more network interfaces. The
	hop addresses are used as hops in the order given. So ping the last address
	the get a traceroute with all the given addresses in that order.`,
		Args: cobra.MinimumNArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, _ string) (
			[]string, cobra.ShellCompDirective,
		) {
			comps := make([]string, 0)
			flags := cobra.ShellCompDirectiveNoFileComp

			if len(args) == 0 {
				if ifaceList, err := net.Interfaces(); err == nil {
					comps = ifinfo.IfUpNameList(ifaceList)
				}
			}

			return comps, flags
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve interface names to interface handles.
			var ifaces []*net.Interface
			for _, ifaceName := range ifaceNames {
				iface, err := net.InterfaceByName(ifaceName)
				if err != nil {
					return fmt.Errorf("interface by name: %s: %v", ifaceName, err)
				}
				ifaces = append(ifaces, iface)
			}

			// Parse hop list into the internal format.
			hopList, err := exceed2go.ParseHopList(args)
			if err != nil {
				return err
			}

			// Load eBPF objects into the kernel and pin it to the bpffs.
			if err := exceed2go.LoadAndPin(); err != nil {
				return fmt.Errorf("load: %v", err)
			}

			// Configure the data plane.
			if err := exceed2go.SetAddrs(hopList); err != nil {
				exceed2go.Remove()
				return fmt.Errorf("set address: %v", err)
			}

			// Attach the program to all interfaces. Removes all state in case
			// of error for any interface.
			for _, iface := range ifaces {
				prog := program(tc, iface.HardwareAddr == nil)
				if err := exceed2go.AttachProg(prog, iface); err != nil {
					exceed2go.Remove()
					return fmt.Errorf("attach program to %s: %v", iface.Name, err)
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(
		&tc,
		"tc",
		tc,
		"Attach to TC instead of XDP generic. Requires linux >= 6.6",
	)

	cmd.Flags().StringSliceVarP(
		&ifaceNames,
		"iface",
		"i",
		ifaceNames,
		"interface to attach to. Can be given repeated or comma-separated.",
	)
	if err := cmd.MarkFlagRequired("iface"); err != nil {
		panic("marking iface flag required must succeed")
	}

	return cmd
}

func program(tc bool, l3 bool) exceed2go.PinFileName {
	if tc {
		if l3 {
			return exceed2go.PinFileNameTCL3Prog
		}
		return exceed2go.PinFileNameTCL2Prog
	}
	if l3 {
		return exceed2go.PinFileNameXDPL3Prog
	}
	return exceed2go.PinFileNameXDPL2Prog
}
