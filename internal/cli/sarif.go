package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifRoot struct {
	Version string  `json:"version"`
	Schema  string  `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Properties sarifProperties `json:"properties,omitempty"`
	Fixes     []sarifFix      `json:"fixes,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifProperties struct {
	Severity     string  `json:"severity"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	EPSSScore    float64 `json:"epss_score,omitempty"`
	KEVListed    bool    `json:"kev_listed"`
	RiskScore    float64 `json:"risk_score,omitempty"`
}

type sarifFix struct {
	Description sarifMessage            `json:"description"`
	ArtifactChanges []sarifArtifactChange `json:"artifactChanges"`
}

type sarifArtifactChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement   `json:"replacements"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifReplacement struct {
	DeletedRegion   sarifRegion `json:"deletedRegion"`
	InsertedContent sarifContent `json:"insertedContent"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type sarifContent struct {
	Text string `json:"text"`
}

func sarifLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "error"
	case "high":
		return "warning"
	default:
		return "note"
	}
}

func writeSARIF(w io.Writer, findings []FindingWithEnrichment, imageRef string) error {
	var results []sarifResult
	for _, f := range findings {
		r := sarifResult{
			RuleID: f.VulnerabilityID,
			Level:  sarifLevel(f.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s@%s: %s", f.PackageName, f.InstalledVersion, f.Title),
			},
			Properties: sarifProperties{
				Severity:     f.Severity,
				FixedVersion: f.FixedVersion,
				EPSSScore:    f.EPSSScore,
				KEVListed:    f.KevListed,
				RiskScore:    f.RiskScore,
			},
		}

		if f.FixedVersion != "" {
			r.Fixes = []sarifFix{
				{
					Description: sarifMessage{
						Text: fmt.Sprintf("Upgrade %s to version %s", f.PackageName, f.FixedVersion),
					},
					ArtifactChanges: []sarifArtifactChange{
						{
							ArtifactLocation: sarifArtifactLocation{
								URI: imageRef,
							},
							Replacements: []sarifReplacement{
								{
									DeletedRegion: sarifRegion{
										StartLine: 1,
										EndLine:   1,
									},
									InsertedContent: sarifContent{
										Text: fmt.Sprintf("%s@%s", f.PackageName, f.FixedVersion),
									},
								},
							},
						},
					},
				},
			}
		}

		results = append(results, r)
	}

	root := sarifRoot{
		Version: "2.1.0",
		Schema:  sarifSchema,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Vullify",
						Version:        "1.0.0",
						InformationURI: "https://vullify.com",
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}
