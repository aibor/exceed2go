package cmd

import (
	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
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
