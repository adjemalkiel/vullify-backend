package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// GHCRCredentials configures GitHub Container Registry (ghcr.io) access and webhooks.
type GHCRCredentials struct {
	GitHubToken   string `json:"github_token"`
	WebhookSecret string `json:"webhook_secret,omitempty"`
}

// GHCR implements RegistryConnector for ghcr.io using a GitHub personal access token or fine-grained token with read:packages.
type GHCR struct {
	RegistryURL string
	HTTPClient  *http.Client

	creds GHCRCredentials
}

// NewGHCR returns a connector with production defaults.
func NewGHCR(c GHCRCredentials) *GHCR {
	return &GHCR{
		RegistryURL: "https://ghcr.io",
		HTTPClient:  http.DefaultClient,
		creds:       c,
	}
}

func (g *GHCR) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return http.DefaultClient
}

func (g *GHCR) regBase() string {
	if g.RegistryURL != "" {
		return strings.TrimRight(g.RegistryURL, "/")
	}
	return "https://ghcr.io"
}

func (g *GHCR) authHeader(req *http.Request) {
	t := strings.TrimSpace(g.creds.GitHubToken)
	if t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}

// TestConnection verifies the registry HTTP API v2 root with a PAT.
func (g *GHCR) TestConnection(ctx context.Context) error {
	if strings.TrimSpace(g.creds.GitHubToken) == "" {
		return fmt.Errorf("ghcr: github_token required")
	}
	cli := g.client()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.regBase()+"/v2/", nil)
	if err != nil {
		return err
	}
	g.authHeader(req)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("ghcr registry: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// ListRepositories is not implemented for GHCR (returns empty catalog).
func (g *GHCR) ListRepositories(ctx context.Context) ([]string, error) {
	return nil, nil
}

// ListTags lists tags via /v2/{repo}/tags/list.
func (g *GHCR) ListTags(ctx context.Context, repository string) ([]string, error) {
	cli := g.client()
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, fmt.Errorf("ghcr: empty repository")
	}
	u := g.regBase() + "/v2/" + ghcrEncodeRepoPath(repository) + "/tags/list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	g.authHeader(req)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ghcr tags: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var page struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("ghcr tags decode: %w", err)
	}
	names := page.Tags
	sort.Strings(names)
	return names, nil
}

// GetDigest resolves digest via HEAD /v2/{repo}/manifests/{tag}.
func (g *GHCR) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	cli := g.client()
	repository = strings.TrimSpace(repository)
	tag = strings.TrimSpace(tag)
	if repository == "" || tag == "" {
		return "", fmt.Errorf("ghcr: repository and tag required")
	}
	path := fmt.Sprintf("%s/v2/%s/manifests/%s", g.regBase(), ghcrEncodeRepoPath(repository), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, path, nil)
	if err != nil {
		return "", err
	}
	g.authHeader(req)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("ghcr manifest: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("ghcr: missing Docker-Content-Digest header")
	}
	return digest, nil
}

func ghcrEncodeRepoPath(repository string) string {
	parts := strings.Split(repository, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
