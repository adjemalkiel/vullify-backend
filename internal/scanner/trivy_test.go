package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTrivyScanner_ScanImage_Success(t *testing.T) {
	t.Parallel()

	reportJSON := `{
  "SchemaVersion": 2,
  "Metadata": {
    "OS": {"Family": "alpine", "Name": "3.19.0"},
    "ImageID": "sha256:abc123",
    "ImageConfig": {"architecture": "amd64", "created": "2024-01-01T00:00:00Z"},
    "Size": 5000000
  },
  "Results": [
    {
      "Target": "alpine:3.19 (alpine 3.19.0)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Packages": [
        {"Name": "musl", "Version": "1.2.4", "Licenses": ["MIT"], "FilePath": "/lib/musl"}
      ],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-1",
          "PkgName": "bash",
          "InstalledVersion": "5.0",
          "FixedVersion": "5.1",
          "Severity": "HIGH",
          "Title": "t",
          "Description": "d",
          "PrimaryURL": "https://example.com",
          "DataSource": {"Name": "debian"},
          "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
          "Layer": {"Digest": "sha256:layer1"}
        }
      ]
    }
  ]
}`
	cycloneDX := `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`
	spdxJSON := `{"spdxVersion":"SPDX-2.3","name":"test"}`

	fake := func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		if name != "trivy" {
			t.Fatalf("unexpected binary %q", name)
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--format json"):
			return []byte(reportJSON), nil, 0, nil
		case strings.Contains(joined, "--format cyclonedx"):
			return []byte(cycloneDX), nil, 0, nil
		case strings.Contains(joined, "--format spdx-json"):
			return []byte(spdxJSON), nil, 0, nil
		default:
			t.Fatalf("unexpected args: %v", args)
			return nil, nil, 1, errors.New("bad")
		}
	}

	s := &TrivyScanner{TrivyPath: "trivy", Exec: fake}
	res, err := s.ScanImage(context.Background(), "alpine:3.19")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("vulns: got %d", len(res.Vulnerabilities))
	}
	v := res.Vulnerabilities[0]
	if v.VulnerabilityID != "CVE-2021-1" || v.PackageName != "bash" || v.DataSource != "debian" {
		t.Fatalf("vuln: %+v", v)
	}
	if v.CVSSV3Score != 7.5 || v.CVSSV3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Fatalf("cvss: score=%f vector=%s", v.CVSSV3Score, v.CVSSV3Vector)
	}
	if v.PrimaryURL != "https://example.com" {
		t.Fatalf("primary_url: %s", v.PrimaryURL)
	}
	if v.LayerDigest != "sha256:layer1" {
		t.Fatalf("layer_digest: %s", v.LayerDigest)
	}
	if string(res.SBOMCycloneDX) != cycloneDX {
		t.Fatalf("cyclonedx: %s", res.SBOMCycloneDX)
	}
	if string(res.SBOMSPDX) != spdxJSON {
		t.Fatalf("spdx: %s", res.SBOMSPDX)
	}
	if res.Metadata == nil || res.Metadata.OS != "alpine 3.19.0" {
		t.Fatalf("metadata: %+v", res.Metadata)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "musl" {
		t.Fatalf("packages: %+v", res.Packages)
	}
}

func TestTrivyScanner_ScanImage_PullFailure(t *testing.T) {
	t.Parallel()

	fake := func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--format json") {
			return nil, []byte("failed to pull image: not found"), 1, errors.New("exit status 1")
		}
		return nil, nil, 0, nil
	}

	s := &TrivyScanner{TrivyPath: "trivy", Exec: fake}
	_, err := s.ScanImage(context.Background(), "example.invalid/foo:tag")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrPullFailure) || !IsPullFailure(err) {
		t.Fatalf("expected ErrPullFailure, got %v", err)
	}
	var te *TrivyError
	if !errors.As(err, &te) || te.Phase != "json" {
		t.Fatalf("expected *TrivyError phase json, got %v", err)
	}
}

func TestTrivyScanner_ScanImage_ScanFailure(t *testing.T) {
	t.Parallel()

	fake := func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--format json") {
			return nil, []byte("internal scanner error"), 2, errors.New("exit status 2")
		}
		return nil, nil, 0, nil
	}

	s := &TrivyScanner{TrivyPath: "trivy", Exec: fake}
	_, err := s.ScanImage(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrScanFailure) || !IsScanFailure(err) {
		t.Fatalf("expected ErrScanFailure, got %v", err)
	}
}

func TestTrivyScanner_ScanImage_InvalidJSONReport(t *testing.T) {
	t.Parallel()

	fake := func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--format json") {
			return []byte(`not json`), nil, 0, nil
		}
		return nil, nil, 0, nil
	}

	s := &TrivyScanner{TrivyPath: "trivy", Exec: fake}
	_, err := s.ScanImage(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "parse trivy json report") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestTrivyScanner_ScanImage_InvalidCycloneDX(t *testing.T) {
	t.Parallel()

	fake := func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--format json"):
			return []byte(`{"Results":[]}`), nil, 0, nil
		case strings.Contains(joined, "--format cyclonedx"):
			return []byte(`not-json`), nil, 0, nil
		default:
			return nil, nil, 1, errors.New("bad args")
		}
	}

	s := &TrivyScanner{TrivyPath: "trivy", Exec: fake}
	_, err := s.ScanImage(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestTrivyScanner_ScanImage_EmptyRef(t *testing.T) {
	t.Parallel()
	s := &TrivyScanner{Exec: func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		t.Fatal("exec should not run")
		return nil, nil, 0, nil
	}}
	_, err := s.ScanImage(context.Background(), "  ")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrivyScanner_Timeout(t *testing.T) {
	t.Parallel()

	fake := func(ctx context.Context, name string, args []string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, []byte(ctx.Err().Error()), 1, ctx.Err()
	}

	s := &TrivyScanner{TrivyPath: "trivy", Timeout: 50 * time.Millisecond, Exec: fake}
	_, err := s.ScanImage(context.Background(), "alpine:3.19")
	if err == nil {
		t.Fatal("expected timeout")
	}
}
