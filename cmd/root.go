// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exceed2go",
		Short: "eBPF TTL responder",
		Long:  `Respond with time exceed ICMP messages to the given IPv6 addresses.`,
	}

	cmd.AddCommand(cleanupCmd())
	cmd.AddCommand(loadCmd())
	cmd.AddCommand(statsCmd())

	return cmd
}
