package scanner

import (
	"context"
	"errors"
)

// ScanResult aggregates vulnerability findings and a CycloneDX SBOM (JSON bytes).
type ScanResult struct {
	Vulnerabilities []VulnResult
	SBOM            []byte // CycloneDX JSON
}

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
}

// Scanner runs container image scans (implemented by TrivyScanner; mock in tests).
type Scanner interface {
	ScanImage(ctx context.Context, imageRef string) (*ScanResult, error)
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
	Phase  string // "json" or "cyclonedx"
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
