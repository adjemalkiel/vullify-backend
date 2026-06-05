package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

var (
	colorCritical = color.New(color.FgHiRed).SprintFunc()
	colorHigh     = color.New(color.FgYellow).SprintFunc()
	colorMedium   = color.New(color.FgHiYellow).SprintFunc()
	colorLow      = color.New(color.FgCyan).SprintFunc()
	colorUnknown  = color.New(color.FgWhite).SprintFunc()
)

func colorSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return colorCritical(strings.ToUpper(s))
	case "high":
		return colorHigh(strings.ToUpper(s))
	case "medium":
		return colorMedium(strings.ToUpper(s))
	case "low":
		return colorLow(strings.ToUpper(s))
	default:
		return colorUnknown(strings.ToUpper(s))
	}
}

func printFindingsTable(rows []Finding) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PACKAGE\tCVE\tSEVERITY\tFIXED")
	for _, f := range rows {
		fix := f.FixedVersion
		if fix == "" {
			fix = "-"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			f.PackageName,
			f.VulnerabilityID,
			colorSeverity(f.Severity),
			fix,
		)
	}
	_ = w.Flush()
}

func printFindingsWithEnrichmentTable(rows []FindingWithEnrichment) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PACKAGE\tCVE\tSEVERITY\tFIXED\tEPSS\tKEV\tRISK")
	for _, f := range rows {
		fix := f.FixedVersion
		if fix == "" {
			fix = "-"
		}
		kev := "-"
		if f.KevListed {
			kev = "YES"
		}
		epss := "-"
		if f.EPSSScore > 0 {
			epss = fmt.Sprintf("%.4f", f.EPSSScore)
		}
		risk := "-"
		if f.RiskScore > 0 {
			risk = fmt.Sprintf("%.1f", f.RiskScore)
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.PackageName,
			f.VulnerabilityID,
			colorSeverity(f.Severity),
			fix,
			epss,
			kev,
			risk,
		)
	}
	_ = w.Flush()
}
