package cmd

import (
	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

// cleanupCmd represents the run command
var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Cleanup the program",
	Long:  `Dettach the XDP program and unload all objects.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		exceed2go.Cleanup()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(cleanupCmd)
}
