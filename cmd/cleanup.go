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
