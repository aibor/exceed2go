package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run INTERFACE TARGET_ADDRESS HOP_ADDRESS ...",
	Short: "Run the program",
	Long: `Attach the XDP program to the interface with the given name. The
	first address is the target address that the packets are matched against.
	The additional addresses are the hops source addresses the time exceeded
	ICMP packets will be sent from in the given order.`,
	Args: cobra.MinimumNArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		ifName := args[0]
		hopAddrs := args[1:]

		objs, err := exceed2go.Load()
		if err != nil {
			return fmt.Errorf("error loading objects: %w", err)
		}
		defer func() {
			if err := objs.Close(); err != nil {
				fmt.Printf("error closing objects: %v", err)
			}
		}()

		for idx, addr := range hopAddrs {
			if err := objs.SetAddr(idx, addr); err != nil {
				return fmt.Errorf("error setting address: %w", err)
			}
		}

		closeFunc, err := objs.AttachProg(ifName)
		if err != nil {
			return fmt.Errorf("error attaching program: %w", err)
		}

		defer func() {
			if err := closeFunc(); err != nil {
				fmt.Printf("error closing objects: %v", err)
			}
		}()

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			}
		}
	},
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		flags := cobra.ShellCompDirectiveNoFileComp

		if len(args) == 0 {
			return exceed2go.LinkUpNameList(), flags
		}

		return exceed2go.IPv6AddrsList(args[0]), flags
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
