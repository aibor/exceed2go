// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"errors"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

func cleanupCmd() *cobra.Command {
	var ifaceNames []string

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Cleanup the program",
		Long:  `Detach the eBPF program and unload all objects.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if len(ifaceNames) == 0 {
				exceed2go.RemoveAll()

				return nil
			}

			var errs []error

			for _, ifaceName := range ifaceNames {
				iface, err := ifaceByName(ifaceName)
				if err != nil {
					errs = append(errs, err)
				}

				exceed2go.RemoveIface(iface.Index)
			}

			return errors.Join(errs...)
		},
	}

	cmd.Flags().StringSliceVarP(
		&ifaceNames,
		"iface",
		"i",
		ifaceNames,
		"interface to clean up. Can be given repeated or comma-separated."+
			" If none is given, all are removed.",
	)

	return cmd
}
