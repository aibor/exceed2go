// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

var ErrNotAttached = errors.New("exceed2go not attached")

func statsCmd() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Print stats of the program.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			iface, err := ifaceByName(ifaceName)
			if err != nil {
				return err
			}

			if !exceed2go.KnownIface(iface.Index) {
				return ErrNotAttached
			}

			stats, err := exceed2go.ReadStats(iface.Index)
			if err != nil {
				return fmt.Errorf("read stats: %w", err)
			}

			for _, stat := range stats {
				cmd.Printf("%-25s  %d\n", stat.Name, stat.Count)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(
		&ifaceName,
		"iface",
		"i",
		ifaceName,
		"interface to read stats for.",
	)

	if err := cmd.MarkFlagRequired("iface"); err != nil {
		panic("marking iface flag required must succeed")
	}

	return cmd
}
