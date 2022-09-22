package cmd

import (
	"fmt"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
)

// statsCmd represents the run command
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Print stats of the program",
	RunE: func(cmd *cobra.Command, args []string) error {
		stats, err := exceed2go.GetStats()
		if err != nil {
			return err
		}
		fmt.Printf("% d\n", stats)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
}
