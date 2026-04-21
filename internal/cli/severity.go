package cli

import (
	"fmt"
	"strings"
)

// severityRank returns ordering: critical highest.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

func parseFailOn(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 4, nil // default high
	}
	r := severityRank(s)
	if r == 0 {
		return 0, fmt.Errorf("invalid --fail-on severity %q (use critical|high|medium|low|unknown)", s)
	}
	return r, nil
}

// MeetsFailThreshold is true if finding severity is at or above threshold (e.g. fail-on high => critical+high).
func MeetsFailThreshold(findingSev string, thresholdRank int) bool {
	return severityRank(findingSev) >= thresholdRank
}
