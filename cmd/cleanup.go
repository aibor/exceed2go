package cmd

import (
	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

func cleanupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Cleanup the program",
		Long:  `Dettach the XDP program and unload all objects.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			exceed2go.Cleanup()

			return nil
		},
	}
}
