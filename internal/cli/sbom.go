package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newSbomCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "sbom <scan_id>",
		Short: "Download SBOM JSON for a completed scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				return fmt.Errorf("--output is required")
			}
			scanID := args[0]
			client := newClient()
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			raw, format, err := client.GetSBOM(ctx, scanID)
			if err != nil {
				return err
			}
			if err := os.WriteFile(output, raw, 0o644); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(os.Stderr, "Wrote SBOM (%s) to %s\n", format, output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (required)")
	return cmd
}
