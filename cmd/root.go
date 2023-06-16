/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exceed2go",
		Short: "XDP TTL responder",
		Long:  `Respond with time exceed ICMP messages to the given IPv6 addresses.`,
	}

	cmd.AddCommand(cleanupCmd())
	cmd.AddCommand(loadCmd())
	cmd.AddCommand(statsCmd())

	return cmd
}
