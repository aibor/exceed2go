// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aibor/exceed2go/internal/exceed2go"
)

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Print stats of the program.",
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := exceed2go.GetStats()
			if err != nil {
				return err
			}
			for _, stat := range stats {
				fmt.Printf("%-25s  %d\n", stat.Name, stat.Count)
			}
			return nil
		},
	}
}
