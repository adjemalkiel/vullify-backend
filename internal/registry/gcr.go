package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GCRCredentials holds either a wrapped service account JSON or the raw key object.
type GCRCredentials struct {
	// ServiceAccountJSON is optional; if empty, the outer credentials JSON is treated as a GCP service account key.
	ServiceAccountJSON json.RawMessage `json:"service_account_json"`
}

// GCR implements RegistryConnector for Google Container Registry (gcr.io) using a service account JSON key.
type GCR struct {
	RegistryURL string
	HTTPClient  *http.Client

	saJSON json.RawMessage
}

// NewGCR builds a GCR connector. Pass GCRCredentials from JSON or use NewGCRFromServiceAccountJSON.
func NewGCR(c GCRCredentials) (*GCR, error) {
	raw, err := resolveGCPServiceAccountJSON(c)
	if err != nil {
		return nil, err
	}
	return &GCR{
		RegistryURL: "https://gcr.io",
		HTTPClient:  http.DefaultClient,
		saJSON:      raw,
	}, nil
}

// NewGCRFromServiceAccountJSON is a convenience for tests and direct use.
func NewGCRFromServiceAccountJSON(saJSON json.RawMessage) (*GCR, error) {
	if len(saJSON) == 0 {
		return nil, fmt.Errorf("gcr: empty service account json")
	}
	return &GCR{
		RegistryURL: "https://gcr.io",
		HTTPClient:  http.DefaultClient,
		saJSON:      saJSON,
	}, nil
}

func resolveGCPServiceAccountJSON(c GCRCredentials) (json.RawMessage, error) {
	if len(c.ServiceAccountJSON) > 0 {
		return c.ServiceAccountJSON, nil
	}
	return nil, fmt.Errorf("gcr: service_account_json required (full GCP service account key JSON)")
}

func parseGCRCredentialsBlob(raw json.RawMessage) (GCRCredentials, error) {
	var c GCRCredentials
	if err := json.Unmarshal(raw, &c); err != nil {
		return GCRCredentials{}, err
	}
	if len(c.ServiceAccountJSON) > 0 {
		return c, nil
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return GCRCredentials{}, err
	}
	if t, _ := probe["type"].(string); t == "service_account" {
		c.ServiceAccountJSON = raw
		return c, nil
	}
	return GCRCredentials{}, fmt.Errorf("gcr: expected service_account_json or GCP service account key JSON")
}

func (g *GCR) client(ctx context.Context) (*http.Client, error) {
	scope := "https://www.googleapis.com/auth/cloud-platform"
	conf, err := google.JWTConfigFromJSON(g.saJSON, scope)
	if err != nil {
		return nil, fmt.Errorf("gcr jwt config: %w", err)
	}
	base := http.DefaultClient
	if g.HTTPClient != nil {
		base = g.HTTPClient
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, base)
	return oauth2.NewClient(ctx, conf.TokenSource(ctx)), nil
}

func (g *GCR) regBase() string {
	if g.RegistryURL != "" {
		return strings.TrimRight(g.RegistryURL, "/")
	}
	return "https://gcr.io"
}

// TestConnection performs a minimal authenticated request to the registry API.
func (g *GCR) TestConnection(ctx context.Context) error {
	cli, err := g.client(ctx)
	if err != nil {
		return err
	}
	u := g.regBase() + "/v2/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("gcr registry: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// ListRepositories uses the Registry v2 _catalog endpoint (paginated via Link header).
func (g *GCR) ListRepositories(ctx context.Context) ([]string, error) {
	cli, err := g.client(ctx)
	if err != nil {
		return nil, err
	}
	var all []string
	next := g.regBase() + "/v2/_catalog?n=100"
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
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
			return nil, fmt.Errorf("gcr catalog: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("gcr catalog decode: %w", err)
		}
		all = append(all, page.Repositories...)
		next = nextCatalogURL(resp.Header.Get("Link"), g.regBase())
	}
	sort.Strings(all)
	return all, nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="next"`)

func nextCatalogURL(linkHeader, regBase string) string {
	if linkHeader == "" {
		return ""
	}
	m := linkNext.FindStringSubmatch(linkHeader)
	if len(m) < 2 {
		return ""
	}
	u := strings.TrimSpace(m[1])
	if strings.HasPrefix(u, "/") {
		return regBase + u
	}
	return u
}

// ListTags lists tags via /v2/{repo}/tags/list.
func (g *GCR) ListTags(ctx context.Context, repository string) ([]string, error) {
	cli, err := g.client(ctx)
	if err != nil {
		return nil, err
	}
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, fmt.Errorf("gcr: empty repository")
	}
	u := g.regBase() + "/v2/" + encodeRepoPath(repository) + "/tags/list"

	var names []string
	for u != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
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
			return nil, fmt.Errorf("gcr tags list: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("gcr tags decode: %w", err)
		}
		names = append(names, page.Tags...)
		next := nextCatalogURL(resp.Header.Get("Link"), g.regBase())
		if next == "" {
			break
		}
		u = next
	}
	sort.Strings(names)
	return names, nil
}

func encodeRepoPath(repository string) string {
	parts := strings.Split(repository, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// GetDigest resolves digest via HEAD /v2/{repo}/manifests/{tag}.
func (g *GCR) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	cli, err := g.client(ctx)
	if err != nil {
		return "", err
	}
	if repository == "" || tag == "" {
		return "", fmt.Errorf("gcr: repository and tag required")
	}
	path := fmt.Sprintf("%s/v2/%s/manifests/%s", g.regBase(), encodeRepoPath(repository), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("gcr manifest: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("gcr: missing Docker-Content-Digest header")
	}
	return digest, nil
}
