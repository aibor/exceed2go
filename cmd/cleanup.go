// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/aibor/exceed2go/internal/exceed2go"
)

func cleanupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Cleanup the program",
		Long:  `Detach the eBPF program and unload all objects.`,
		Run: func(_ *cobra.Command, _ []string) {
			exceed2go.Remove()
		},
	}
}
