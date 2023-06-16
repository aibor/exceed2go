package cmd

import (
	"fmt"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

func loadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "load INTERFACE HOP_ADDRESS ...",
		Short: "Load and configure the program",
		Long: `Attach the XDP program to the interface with the given name. The
	hop addresses are used as hops in the order given. So ping the last address
	the get a traceroute with all the given addresses in that order.`,
		Args: cobra.MinimumNArgs(3),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) (
			[]string, cobra.ShellCompDirective,
		) {
			flags := cobra.ShellCompDirectiveNoFileComp

			if len(args) == 0 {
				return exceed2go.IfUpNameList(), flags
			}

			return exceed2go.IPv6AddrsList(args[0]), flags
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ifName := args[0]
			hopAddrs := args[1:]

			objs, err := exceed2go.Load()
			if err != nil {
				return fmt.Errorf("load objects: %v", err)
			}

			defer objs.Close()

			if err := objs.PinObjs(); err != nil {
				return fmt.Errorf("pin maps: %v", err)
			}

			for idx, addr := range hopAddrs {
				if err := exceed2go.SetAddr(idx, addr); err != nil {
					exceed2go.Cleanup()
					return fmt.Errorf("set address: %v", err)
				}
			}

			if err := objs.AttachProg(ifName); err != nil {
				exceed2go.Cleanup()
				return fmt.Errorf("attach program: %v", err)
			}

			return nil
		},
	}
}
