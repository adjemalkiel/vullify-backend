package scanner

import (
	"context"
	"errors"
)

// VulnResult is a single finding from a Trivy JSON report.
type VulnResult struct {
	VulnerabilityID  string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Title            string
	Description      string
	DataSource       string
	CVSSV3Score      float64
	CVSSV3Vector     string
	PrimaryURL       string
	LayerDigest      string
	LayerIndex       int
}

// PackageResult is a package entry from the SBOM inventory.
type PackageResult struct {
	Name        string
	Version     string
	Type        string
	LayerDigest string
	Licenses    []string
	FilePath    string
}

// MisconfigResult is a misconfiguration finding.
type MisconfigResult struct {
	Type        string
	CheckID     string
	Title       string
	Description string
	Severity    string
	Resolution  string
	FilePath    string
	StartLine   int
	EndLine     int
}

// SecretResult is a detected secret.
type SecretResult struct {
	RuleID      string
	Category    string
	Severity    string
	Title       string
	MatchText   string
	FilePath    string
	StartLine   int
	EndLine     int
	LayerDigest string
}

// ScanMetadata holds image-level metadata from Trivy.
type ScanMetadata struct {
	OS           string
	Architecture string
	ImageID      string
	Created      string
	ImageSize    int64
	LayerCount   int
	BaseImage    string
}

// ScanResult aggregates vulnerability findings and SBOMs in multiple formats.
type ScanResult struct {
	Vulnerabilities  []VulnResult
	Packages         []PackageResult
	Misconfigurations []MisconfigResult
	Secrets          []SecretResult
	Metadata         *ScanMetadata
	SBOMCycloneDX    []byte
	SBOMSPDX         []byte
}

// ScanImageOpts carries optional registry credentials for authenticated pulls.
type ScanImageOpts struct {
	RegistryUsername string
	RegistryPassword string
}

// Scanner runs container image scans (implemented by TrivyScanner; mock in tests).
type Scanner interface {
	ScanImage(ctx context.Context, imageRef string, opts *ScanImageOpts) (*ScanResult, error)
}

// Sentinel errors for classification (use errors.Is).
var (
	ErrPullFailure = errors.New("trivy: image pull or registry access failed")
	ErrScanFailure = errors.New("trivy: scan execution failed")
)

// ErrorKind distinguishes pull/registry problems from scan/runtime problems.
type ErrorKind int

const (
	KindPull ErrorKind = iota
	KindScan
)

// TrivyError wraps a failed trivy invocation with stderr and classification.
type TrivyError struct {
	Kind   ErrorKind
	Phase  string // "json", "cyclonedx", or "spdx"
	Stderr string
	Exit   int
	Err    error
}

func (e *TrivyError) Error() string {
	if e == nil {
		return ""
	}
	msg := "trivy " + e.Phase + " failed"
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *TrivyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is supports errors.Is(err, ErrPullFailure) and errors.Is(err, ErrScanFailure).
func (e *TrivyError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrPullFailure:
		return e.Kind == KindPull
	case ErrScanFailure:
		return e.Kind == KindScan
	default:
		return false
	}
}

// IsPullFailure reports whether err matches ErrPullFailure (including via *TrivyError).
func IsPullFailure(err error) bool {
	return errors.Is(err, ErrPullFailure)
}

// IsScanFailure reports whether err matches ErrScanFailure (including via *TrivyError).
func IsScanFailure(err error) bool {
	return errors.Is(err, ErrScanFailure)
}
