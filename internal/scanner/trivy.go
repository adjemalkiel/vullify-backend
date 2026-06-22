package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ExecFunc runs a command like exec.CommandContext; used for tests (fake trivy).
type ExecFunc func(ctx context.Context, name string, args []string, env []string) (stdout, stderr []byte, exitCode int, err error)

// TrivyScanner runs the trivy CLI as a subprocess.
type TrivyScanner struct {
	TrivyPath string
	Timeout   time.Duration
	Exec      ExecFunc

	// ExtraEnv holds environment variables set on every trivy invocation
	// (e.g. TRIVY_USERNAME, TRIVY_PASSWORD for registry auth).
	ExtraEnv []string
}

// ScanImage implements Scanner.
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string, opts *ScanImageOpts) (*ScanResult, error) {
	if strings.TrimSpace(imageRef) == "" {
		return nil, fmt.Errorf("scanner: empty image reference")
	}

	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := s.TrivyPath
	if path == "" {
		path = "trivy"
	}

	var extraEnv []string
	if opts != nil {
		if opts.RegistryUsername != "" {
			extraEnv = append(extraEnv, "TRIVY_USERNAME="+opts.RegistryUsername)
		}
		if opts.RegistryPassword != "" {
			extraEnv = append(extraEnv, "TRIVY_PASSWORD="+opts.RegistryPassword)
		}
	}
	s.ExtraEnv = extraEnv

	run := s.execFn()

	jsonArgs := []string{
		"image",
		"--format", "json",
		"--scanners", "vuln,misconfig,secret,license",
		"--list-all-pkgs",
		"--pkg-types", "os,library",
		"--quiet",
		"--timeout", "10m",
		imageRef,
	}
	stdout, stderr, exit, runErr := run(ctx, path, jsonArgs, nil)
	if runErr != nil || exit != 0 {
		return nil, classifyAndWrap("json", stderr, exit, runErr)
	}

	result, err := parseTrivyJSONReport(stdout)
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
		"--scanners", "vuln,misconfig,secret,license",
		imageRef,
	}
	sbomOut, sbomErrText, sbomExit, sbomRunErr := run(ctx, path, sbomArgs, nil)
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
	result.SBOMCycloneDX = bytes.Clone(sbomOut)

	spdxArgs := []string{
		"image",
		"--format", "spdx-json",
		imageRef,
	}
	spdxOut, spdxErrText, spdxExit, spdxRunErr := run(ctx, path, spdxArgs, nil)
	if spdxRunErr != nil || spdxExit != 0 {
		return nil, classifyAndWrap("spdx", spdxErrText, spdxExit, spdxRunErr)
	}
	if !json.Valid(spdxOut) {
		return nil, &TrivyError{
			Kind:   KindScan,
			Phase:  "spdx",
			Stderr: string(spdxErrText),
			Exit:   spdxExit,
			Err:    errors.New("spdx output is not valid JSON"),
		}
	}
	result.SBOMSPDX = bytes.Clone(spdxOut)

	return result, nil
}

func (s *TrivyScanner) execFn() ExecFunc {
	extra := s.ExtraEnv
	if s.Exec != nil {
		return func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, int, error) {
			return s.Exec(ctx, name, args, append(env, extra...))
		}
	}
	return func(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, int, error) {
		return defaultExec(ctx, name, args, append(env, extra...))
	}
}

func defaultExec(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
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
	if strings.Contains(s, "tls: ") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "dial tcp") && strings.Contains(s, "lookup") {
		return KindPull
	}
	return KindScan
}

func parseTrivyJSONReport(data []byte) (*ScanResult, error) {
	var report struct {
		Metadata *struct {
			OS *struct {
				Family string `json:"Family"`
				Name   string `json:"Name"`
			} `json:"OS"`
			ImageConfig struct {
				Architecture string `json:"architecture"`
				Created      string `json:"created"`
			} `json:"ImageConfig"`
			ImageID string `json:"ImageID"`
			Size    int64  `json:"Size"`
		} `json:"Metadata"`
		Results []struct {
			Target          string `json:"Target"`
			Class           string `json:"Class"`
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				VulnerabilityID  string          `json:"VulnerabilityID"`
				PkgName          string          `json:"PkgName"`
				InstalledVersion string          `json:"InstalledVersion"`
				FixedVersion     string          `json:"FixedVersion"`
				Severity         string          `json:"Severity"`
				Title            string          `json:"Title"`
				Description      string          `json:"Description"`
				PrimaryURL       string          `json:"PrimaryURL"`
				DataSource       json.RawMessage `json:"DataSource"`
				CVSS             struct {
					Nvd *struct {
						V3Score  float64 `json:"V3Score"`
						V3Vector string  `json:"V3Vector"`
					} `json:"nvd"`
				} `json:"CVSS"`
				Layer *struct {
					Digest string `json:"Digest"`
				} `json:"Layer"`
			} `json:"Vulnerabilities"`
			Packages []struct {
				Name      string   `json:"Name"`
				Version   string   `json:"Version"`
				Licenses  []string `json:"Licenses"`
				Layer     *struct {
					Digest string `json:"Digest"`
				} `json:"Layer"`
				FilePath string `json:"FilePath"`
			} `json:"Packages"`
			Misconfigurations []struct {
				Type        string `json:"Type"`
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
				Resolution  string `json:"Resolution"`
				CauseMetadata *struct {
					Resource  string `json:"Resource"`
					StartLine int    `json:"StartLine"`
					EndLine   int    `json:"EndLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
			Secrets []struct {
				RuleID    string `json:"RuleID"`
				Category  string `json:"Category"`
				Severity  string `json:"Severity"`
				Title     string `json:"Title"`
				Match     string `json:"Match"`
				Code *struct {
					Lines []struct {
						Number int `json:"Number"`
					} `json:"Lines"`
				} `json:"Code"`
				Layer *struct {
					Digest string `json:"Digest"`
				} `json:"Layer"`
			} `json:"Secrets"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	result := &ScanResult{}

	if report.Metadata != nil {
		meta := &ScanMetadata{
			ImageID:   report.Metadata.ImageID,
			ImageSize: report.Metadata.Size,
		}
		if report.Metadata.OS != nil {
			if report.Metadata.OS.Family != "" {
				meta.OS = report.Metadata.OS.Family
				if report.Metadata.OS.Name != "" {
					meta.OS += " " + report.Metadata.OS.Name
				}
			}
		}
		meta.Architecture = report.Metadata.ImageConfig.Architecture
		meta.Created = report.Metadata.ImageConfig.Created
		result.Metadata = meta
	}

	for _, res := range report.Results {
		layerIndex := 0
		switch res.Class {
		case "os-pkgs", "lang-pkgs":
			for _, p := range res.Packages {
				pkg := PackageResult{
					Name:     p.Name,
					Version:  p.Version,
					Type:     res.Type,
					Licenses: p.Licenses,
					FilePath: p.FilePath,
				}
				if p.Layer != nil {
					pkg.LayerDigest = p.Layer.Digest
				}
				result.Packages = append(result.Packages, pkg)
			}
			for _, v := range res.Vulnerabilities {
				vuln := VulnResult{
					VulnerabilityID:  v.VulnerabilityID,
					PackageName:      v.PkgName,
					InstalledVersion: v.InstalledVersion,
					FixedVersion:     v.FixedVersion,
					Severity:         v.Severity,
					Title:            v.Title,
					Description:      v.Description,
					PrimaryURL:       v.PrimaryURL,
					DataSource:       stringifyDataSource(v.DataSource),
					LayerIndex:       layerIndex,
				}
				if v.CVSS.Nvd != nil {
					vuln.CVSSV3Score = v.CVSS.Nvd.V3Score
					vuln.CVSSV3Vector = v.CVSS.Nvd.V3Vector
				}
				if v.Layer != nil {
					vuln.LayerDigest = v.Layer.Digest
				}
				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			}
			layerIndex++

		case "config":
			for _, m := range res.Misconfigurations {
				mis := MisconfigResult{
					Type:        m.Type,
					CheckID:     m.ID,
					Title:       m.Title,
					Description: m.Description,
					Severity:    m.Severity,
					Resolution:  m.Resolution,
				}
				if m.CauseMetadata != nil {
					mis.FilePath = m.CauseMetadata.Resource
					mis.StartLine = m.CauseMetadata.StartLine
					mis.EndLine = m.CauseMetadata.EndLine
				}
				result.Misconfigurations = append(result.Misconfigurations, mis)
			}

		case "secret":
			for _, sec := range res.Secrets {
				secret := SecretResult{
					RuleID:   sec.RuleID,
					Category: sec.Category,
					Severity: sec.Severity,
					Title:    sec.Title,
					MatchText: sec.Match,
				}
				if sec.Code != nil && len(sec.Code.Lines) > 0 {
					secret.StartLine = sec.Code.Lines[0].Number
					secret.EndLine = sec.Code.Lines[len(sec.Code.Lines)-1].Number
				}
				if sec.Layer != nil {
					secret.LayerDigest = sec.Layer.Digest
				}
				result.Secrets = append(result.Secrets, secret)
			}
		}
	}

	return result, nil
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
