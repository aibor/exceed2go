package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/aibor/exceed2go/internal/ifinfo"
)

func loadCmd() *cobra.Command {
	var tc bool

	cmd := &cobra.Command{
		Use:   "load INTERFACE HOP_ADDRESS ...",
		Short: "Load and configure the program",
		Long: `Attach the eBPF program to the interface with the given name. The
	hop addresses are used as hops in the order given. So ping the last address
	the get a traceroute with all the given addresses in that order.`,
		Args: cobra.MinimumNArgs(3),
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
			iface, err := net.InterfaceByName(args[0])
			if err != nil {
				return fmt.Errorf("interface by name: %s: %v", args[0], err)
			}

			hopList, err := exceed2go.ParseHopList(args[1:])
			if err != nil {
				return err
			}

			if err := exceed2go.LoadAndPin(); err != nil {
				return fmt.Errorf("load: %v", err)
			}

			if err := exceed2go.SetAddrs(hopList); err != nil {
				exceed2go.Remove()
				return fmt.Errorf("set address: %v", err)
			}

			prog := exceed2go.PinFileNameXDPProg
			if tc {
				prog = exceed2go.PinFileNameTCProg
			}

			if err := exceed2go.AttachProg(prog, iface); err != nil {
				exceed2go.Remove()
				return fmt.Errorf("attach program: %v", err)
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

	return cmd
}
