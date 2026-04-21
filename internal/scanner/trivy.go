package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ExecFunc runs a command like exec.CommandContext; used for tests (fake trivy).
// Returns stdout, stderr, exit code, and err (non-nil usually when exit != 0).
type ExecFunc func(ctx context.Context, name string, args []string) (stdout, stderr []byte, exitCode int, err error)

// TrivyScanner runs the trivy CLI as a subprocess.
type TrivyScanner struct {
	// TrivyPath is the trivy binary name or path (default: "trivy").
	TrivyPath string
	// Timeout bounds the entire ScanImage (both subprocesses). Zero means 5 minutes.
	Timeout time.Duration
	// Exec, if non-nil, is used instead of the real exec.CommandContext runner.
	Exec ExecFunc
}

// ScanImage implements Scanner.
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string) (*ScanResult, error) {
	if strings.TrimSpace(imageRef) == "" {
		return nil, fmt.Errorf("scanner: empty image reference")
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := s.TrivyPath
	if path == "" {
		path = "trivy"
	}

	run := s.execFn()

	jsonArgs := []string{
		"image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		imageRef,
	}
	stdout, stderr, exit, runErr := run(ctx, path, jsonArgs)
	if runErr != nil || exit != 0 {
		return nil, classifyAndWrap("json", stderr, exit, runErr)
	}

	vulns, err := parseTrivyJSONReport(stdout)
	if err != nil {
		return nil, &TrivyError{
			Kind:   KindScan,
			Phase:  "json",
			Stderr: string(stderr),
			Exit:   exit,
			Err:    fmt.Errorf("parse trivy json report: %w", err),
		}
	}

	sbomArgs := []string{
		"image",
		"--format", "cyclonedx",
		imageRef,
	}
	sbomOut, sbomErrText, sbomExit, sbomRunErr := run(ctx, path, sbomArgs)
	if sbomRunErr != nil || sbomExit != 0 {
		return nil, classifyAndWrap("cyclonedx", sbomErrText, sbomExit, sbomRunErr)
	}
	if !json.Valid(sbomOut) {
		return nil, &TrivyError{
			Kind:   KindScan,
			Phase:  "cyclonedx",
			Stderr: string(sbomErrText),
			Exit:   sbomExit,
			Err:    errors.New("cyclonedx output is not valid JSON"),
		}
	}

	return &ScanResult{
		Vulnerabilities: vulns,
		SBOM:            bytes.Clone(sbomOut),
	}, nil
}

func (s *TrivyScanner) execFn() ExecFunc {
	if s.Exec != nil {
		return s.Exec
	}
	return defaultExec
}

func defaultExec(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return stdout.Bytes(), stderr.Bytes(), -1, err
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, err
}

func classifyAndWrap(phase string, stderr []byte, exit int, runErr error) error {
	text := strings.TrimSpace(string(stderr))
	kind := classifyTrivyFailure(text, exit)
	return &TrivyError{
		Kind:   kind,
		Phase:  phase,
		Stderr: text,
		Exit:   exit,
		Err:    runErr,
	}
}

func classifyTrivyFailure(stderr string, exit int) ErrorKind {
	s := strings.ToLower(stderr)
	// Heuristic: registry / image availability issues.
	if strings.Contains(s, "failed to pull") ||
		strings.Contains(s, "unable to pull") ||
		strings.Contains(s, "error pulling") ||
		strings.Contains(s, "pull access denied") ||
		strings.Contains(s, "repository does not exist") ||
		strings.Contains(s, "repository not found") ||
		strings.Contains(s, "manifest unknown") ||
		strings.Contains(s, "not found: manifest") ||
		strings.Contains(s, "denied: requested access") ||
		strings.Contains(s, "authorization failed") ||
		strings.Contains(s, "no match for platform") && strings.Contains(s, "manifest") {
		return KindPull
	}
	// OCI/registry connection issues often mention transport.
	if strings.Contains(s, "tls: ") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "dial tcp") && strings.Contains(s, "lookup") {
		return KindPull
	}
	return KindScan
}

func parseTrivyJSONReport(data []byte) ([]VulnResult, error) {
	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string          `json:"VulnerabilityID"`
				PkgName          string          `json:"PkgName"`
				InstalledVersion string          `json:"InstalledVersion"`
				FixedVersion     string          `json:"FixedVersion"`
				Severity         string          `json:"Severity"`
				Title            string          `json:"Title"`
				Description      string          `json:"Description"`
				DataSource       json.RawMessage `json:"DataSource"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	var out []VulnResult
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			out = append(out, VulnResult{
				VulnerabilityID:  v.VulnerabilityID,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         v.Severity,
				Title:            v.Title,
				Description:      v.Description,
				DataSource:       stringifyDataSource(v.DataSource),
			})
		}
	}
	return out, nil
}

func stringifyDataSource(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Name string `json:"Name"`
		ID   string `json:"ID"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if obj.Name != "" {
			return obj.Name
		}
		return obj.ID
	}
	return strings.TrimSpace(string(raw))
}

var _ Scanner = (*TrivyScanner)(nil)
