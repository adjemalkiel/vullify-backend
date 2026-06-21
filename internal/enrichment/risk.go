package enrichment

// CalculateRiskScore computes a composite risk score (0-100) from vulnerability attributes.
//
// Scoring breakdown:
//   - CVSS contribution: cvss * 3.0 (max 30 points)
//   - EPSS contribution: epss * 30.0 (max 30 points)
//   - KEV listed: +20 points
//   - Exploit available: +10 points
//   - Fix available: +10 points (actionable targets are higher priority)
func CalculateRiskScore(cvss, epss float64, isKev, hasExploit, hasFix bool) float64 {
	score := 0.0

	score += cvss * 3.0        // max 30
	score += epss * 30.0        // max 30
	if isKev {
		score += 20.0
	}
	if hasExploit {
		score += 10.0
	}
	if hasFix {
		score += 10.0
	}

	if score > 100.0 {
		score = 100.0
	}
	return score
}
