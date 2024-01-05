package cmd

import (
	"fmt"

	"github.com/aibor/exceed2go/internal/exceed2go"
	"github.com/spf13/cobra"
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
