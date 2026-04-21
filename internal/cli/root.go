package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	apiToken  string
	timeout   time.Duration
)

// Execute runs the vullify CLI.
func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "vullify",
		Short: "Vullify API client",
	}
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:8080", "Vullify API base URL")
	rootCmd.PersistentFlags().StringVar(&apiToken, "token", "", "API bearer token (optional)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Minute, "Overall timeout for long operations (e.g. scan wait)")

	rootCmd.AddCommand(newScanCmd(), newResultsCmd(), newSbomCmd())

	return rootCmd.ExecuteContext(context.Background())
}
