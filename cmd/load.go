// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"net"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
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
hop addresses are used as hops in the order given. So ping the last
address the get a traceroute with all the given addresses in that order.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			// Resolve interface names to interface handles.
			var ifaces []*net.Interface
			for _, ifaceName := range ifaceNames {
				iface, err := ifaceByName(ifaceName)
				if err != nil {
					return err
				}
				ifaces = append(ifaces, iface)
			}

			// Parse hop list into the internal format.
			hopList, err := exceed2go.ParseHopList(args)
			if err != nil {
				return fmt.Errorf("parse hop list: %w", err)
			}

			mode := exceed2go.ModeXDP
			if tc {
				mode = exceed2go.ModeTC
			}

			// Attach the program to all interfaces.
			for _, iface := range ifaces {
				layer := exceed2go.Layer2
				if iface.HardwareAddr == nil {
					layer = exceed2go.Layer3
				}

				opts := exceed2go.AttachOptions{
					IfaceIndex: iface.Index,
					HopList:    hopList,
					Mode:       mode,
					Layer:      layer,
				}
				if err := exceed2go.Attach(opts); err != nil {
					return fmt.Errorf("attach to %s: %v", iface.Name, err)
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

	if err := cmd.RegisterFlagCompletionFunc("iface", ifaceCompletion); err != nil {
		panic("registering iface completion must succeed")
	}

	return cmd
}
