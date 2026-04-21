package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newResultsCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "results <scan_id>",
		Short: "Fetch and display scan results",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]
			if format != "table" && format != "json" {
				return fmt.Errorf("--format must be table or json")
			}
			client := newClient()
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			scan, err := client.GetScan(ctx, scanID)
			if err != nil {
				return err
			}
			findings, err := client.ListAllFindings(ctx, scanID)
			if err != nil {
				return err
			}

			switch format {
			case "json":
				out := map[string]any{
					"scan":     scan,
					"findings": findings,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			default:
				printFindingsTable(findings)
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table or json")
	return cmd
}
