package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		failOn        string
		failOnKEV     bool
		failOnUnfixed bool
		epssThreshold float64
		outputFormat  string
	)
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

			if outputFormat != "table" && outputFormat != "json" && outputFormat != "sarif" {
				return fmt.Errorf("--output must be table, json, or sarif")
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

			needsEnrichment := failOnKEV || failOnUnfixed || epssThreshold > 0 || outputFormat == "json" || outputFormat == "sarif"
			var enriched []FindingWithEnrichment
			var findings []Finding

			if needsEnrichment {
				enriched, err = client.ListAllFindingsWithEnrichment(ctx, scanID)
				if err != nil {
					return err
				}
			} else {
				findings, err = client.ListAllFindings(ctx, scanID)
				if err != nil {
					return err
				}
			}

			// Output.
			switch outputFormat {
			case "json":
				out := json.NewEncoder(os.Stdout)
				out.SetIndent("", "  ")
				if err := out.Encode(enriched); err != nil {
					return err
				}
			case "sarif":
				if err := writeSARIF(os.Stdout, enriched, imageRef); err != nil {
					return err
				}
			default:
				if needsEnrichment {
					printFindingsWithEnrichmentTable(enriched)
				} else {
					printFindingsTable(findings)
				}
			}

			// Evaluate policy gates.
			policyFailed := false
			var policyViolations []string

			if needsEnrichment {
				for _, f := range enriched {
					if MeetsFailThreshold(f.Severity, thr) {
						policyFailed = true
						policyViolations = append(policyViolations,
							fmt.Sprintf("severity threshold: %s finding (%s in %s)", f.Severity, f.VulnerabilityID, f.PackageName))
					}
					if failOnKEV && f.KevListed {
						policyFailed = true
						policyViolations = append(policyViolations,
							fmt.Sprintf("KEV listed: %s (%s)", f.VulnerabilityID, f.PackageName))
					}
					if failOnUnfixed && f.FixedVersion == "" {
						policyFailed = true
						policyViolations = append(policyViolations,
							fmt.Sprintf("unfixed: %s (%s@%s)", f.VulnerabilityID, f.PackageName, f.InstalledVersion))
					}
					if epssThreshold > 0 && f.EPSSScore > epssThreshold {
						policyFailed = true
						policyViolations = append(policyViolations,
							fmt.Sprintf("EPSS threshold (%.2f): %s (%.4f) in %s", epssThreshold, f.VulnerabilityID, f.EPSSScore, f.PackageName))
					}
				}
			} else {
				for _, f := range findings {
					if MeetsFailThreshold(f.Severity, thr) {
						policyFailed = true
						policyViolations = append(policyViolations,
							fmt.Sprintf("severity threshold: %s finding (%s in %s)", f.Severity, f.VulnerabilityID, f.PackageName))
					}
				}
			}

			if policyFailed {
				fmt.Fprintln(os.Stderr, "\nPolicy violations:")
				for _, v := range policyViolations {
					fmt.Fprintf(os.Stderr, "  - %s\n", v)
				}
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Exit 1 if any finding is this severity or higher (critical|high|medium|low|unknown)")
	cmd.Flags().BoolVar(&failOnKEV, "fail-on-kev", false, "Exit 1 if any finding is listed in CISA KEV")
	cmd.Flags().BoolVar(&failOnUnfixed, "fail-on-unfixed", false, "Exit 1 if any finding has no fixed version")
	cmd.Flags().Float64Var(&epssThreshold, "epss-threshold", 0.0, "Exit 1 if any finding exceeds EPSS score threshold (0.0 = disabled)")
	cmd.Flags().StringVar(&outputFormat, "output", "table", "Output format: table, json, or sarif")
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
