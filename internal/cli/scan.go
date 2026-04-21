package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var failOn string
	cmd := &cobra.Command{
		Use:   "scan <image_ref>",
		Short: "Create a scan by image ref, wait for completion, print findings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageRef := args[0]
			thr, err := parseFailOn(failOn)
			if err != nil {
				return err
			}

			client := newClient()
			baseCtx := cmd.Context()
			if baseCtx == nil {
				baseCtx = context.Background()
			}
			ctx, cancel := context.WithTimeout(baseCtx, timeout)
			defer cancel()

			s := spinner.New(spinner.CharSets[9], 120*time.Millisecond)
			s.Writer = os.Stderr
			s.Suffix = " creating scan..."
			s.Start()

			scanID, err := client.CreateScanByRef(ctx, imageRef)
			if err != nil {
				s.Stop()
				return err
			}
			short := scanID
			if len(short) > 8 {
				short = short[:8]
			}
			s.Suffix = fmt.Sprintf(" waiting for scan %s...", short)

			st, err := pollUntilDone(ctx, client, scanID, 2*time.Second, func(status string) {
				s.Suffix = fmt.Sprintf(" scan %s — %s", short, status)
			})
			s.Stop()
			if err != nil {
				return fmt.Errorf("scan %s: %w", scanID, err)
			}
			if st == "failed" {
				m, _ := client.GetScan(context.Background(), scanID)
				msg := ""
				if m != nil {
					if em, ok := m["error_message"].(string); ok {
						msg = em
					}
				}
				fmt.Fprintf(os.Stderr, "scan failed: %s\n", msg)
				os.Exit(1)
			}

			findings, err := client.ListAllFindings(ctx, scanID)
			if err != nil {
				return err
			}
			printFindingsTable(findings)

			for _, f := range findings {
				if MeetsFailThreshold(f.Severity, thr) {
					fmt.Fprintf(os.Stderr, "\nexit 1: found %s finding (fail-on threshold)\n", f.Severity)
					os.Exit(1)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Exit 1 if any finding is this severity or higher (critical|high|medium|low|unknown)")
	return cmd
}

func pollUntilDone(ctx context.Context, c *Client, scanID string, interval time.Duration, onStatus func(string)) (string, error) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		m, err := c.GetScan(ctx, scanID)
		if err != nil {
			return "", err
		}
		st, _ := m["status"].(string)
		if onStatus != nil {
			onStatus(st)
		}
		switch st {
		case "completed", "failed":
			return st, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-tick.C:
		}
	}
}
