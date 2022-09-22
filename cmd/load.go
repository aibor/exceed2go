package cmd

import (
	"fmt"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

// loadCmd represents the run command
var loadCmd = &cobra.Command{
	Use:   "load INTERFACE TARGET_ADDRESS HOP_ADDRESS ...",
	Short: "Load and configure the program",
	Long: `Attach the XDP program to the interface with the given name. The
	first address is the target address that the packets are matched against.
	The additional addresses are the hops source addresses the time exceeded
	ICMP packets will be sent from in the given order.`,
	Args: cobra.MinimumNArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		ifName := args[0]
		hopAddrs := args[1:]

		err := exceed2go.LoadAndPin()
		if err != nil {
			return fmt.Errorf("error loading objects: %w", err)
		}

		for idx, addr := range hopAddrs {
			if err := exceed2go.SetAddr(idx, addr); err != nil {
				exceed2go.Cleanup()
				return fmt.Errorf("error setting address: %w", err)
			}
		}

		if err := exceed2go.AttachProg(ifName); err != nil {
			exceed2go.Cleanup()
			return fmt.Errorf("error attaching program: %w", err)
		}

		return nil
	},
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		flags := cobra.ShellCompDirectiveNoFileComp

		if len(args) == 0 {
			return exceed2go.IfUpNameList(), flags
		}

		return exceed2go.IPv6AddrsList(args[0]), flags
	},
}

func init() {
	rootCmd.AddCommand(loadCmd)
}
