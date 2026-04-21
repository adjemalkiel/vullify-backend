package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DockerHubCredentials configures Hub + Registry API access.
// For private namespaces, set Username and Password (or Hub access token as password).
// Namespace defaults to Username when empty (public namespaces can use the org name with empty password for anonymous Hub API where allowed).
type DockerHubCredentials struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Namespace string `json:"namespace,omitempty"`
	// WebhookSecret is used to validate inbound Docker Hub webhooks (Authorization: Bearer or X-Webhook-Token).
	WebhookSecret string `json:"webhook_secret,omitempty"`
}

// DockerHub implements RegistryConnector for Docker Hub (Hub API v2 + Registry HTTP API v2).
type DockerHub struct {
	HubAPIURL   string
	AuthURL     string
	RegistryURL string
	HTTPClient  *http.Client

	creds DockerHubCredentials
}

// NewDockerHub returns a connector with production defaults.
func NewDockerHub(c DockerHubCredentials) *DockerHub {
	return &DockerHub{
		HubAPIURL:   "https://hub.docker.com",
		AuthURL:     "https://auth.docker.io",
		RegistryURL: "https://registry-1.docker.io",
		HTTPClient:  http.DefaultClient,
		creds:       c,
	}
}

func (d *DockerHub) client() *http.Client {
	if d.HTTPClient != nil {
		return d.HTTPClient
	}
	return http.DefaultClient
}

func (d *DockerHub) hubBase() string {
	if d.HubAPIURL != "" {
		return strings.TrimRight(d.HubAPIURL, "/")
	}
	return "https://hub.docker.com"
}

func (d *DockerHub) authBase() string {
	if d.AuthURL != "" {
		return strings.TrimRight(d.AuthURL, "/")
	}
	return "https://auth.docker.io"
}

func (d *DockerHub) regBase() string {
	if d.RegistryURL != "" {
		return strings.TrimRight(d.RegistryURL, "/")
	}
	return "https://registry-1.docker.io"
}

func (d *DockerHub) namespace() string {
	if d.creds.Namespace != "" {
		return d.creds.Namespace
	}
	return d.creds.Username
}

func (d *DockerHub) parseRepo(repository string) (namespace, repo string) {
	repository = strings.TrimSpace(repository)
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return d.namespace(), parts[0]
}

// TestConnection verifies Hub API access for the configured namespace.
func (d *DockerHub) TestConnection(ctx context.Context) error {
	ns := d.namespace()
	if ns == "" {
		return fmt.Errorf("dockerhub: namespace or username required")
	}
	u := fmt.Sprintf("%s/v2/repositories/%s/?page_size=1", d.hubBase(), url.PathEscape(ns))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	d.applyHubAuth(req)
	resp, err := d.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("dockerhub hub api: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (d *DockerHub) applyHubAuth(req *http.Request) {
	if d.creds.Username != "" {
		req.SetBasicAuth(d.creds.Username, d.creds.Password)
	}
}

// ListRepositories returns image names as "namespace/repo" from the Hub API.
func (d *DockerHub) ListRepositories(ctx context.Context) ([]string, error) {
	ns := d.namespace()
	if ns == "" {
		return nil, fmt.Errorf("dockerhub: namespace or username required")
	}
	var out []string
	next := fmt.Sprintf("%s/v2/repositories/%s/", d.hubBase(), url.PathEscape(ns))
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		d.applyHubAuth(req)
		resp, err := d.client().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("dockerhub list repos: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
			Next *string `json:"next"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("dockerhub list repos decode: %w", err)
		}
		for _, r := range page.Results {
			out = append(out, ns+"/"+r.Name)
		}
		if page.Next == nil || *page.Next == "" {
			break
		}
		next = *page.Next
	}
	return out, nil
}

// ListTags lists tag names via Hub API (works for public and private when authenticated).
func (d *DockerHub) ListTags(ctx context.Context, repository string) ([]string, error) {
	ns, repo := d.parseRepo(repository)
	if ns == "" || repo == "" {
		return nil, fmt.Errorf("dockerhub: invalid repository %q", repository)
	}
	var out []string
	next := fmt.Sprintf("%s/v2/repositories/%s/%s/tags", d.hubBase(), url.PathEscape(ns), url.PathEscape(repo))
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		d.applyHubAuth(req)
		resp, err := d.client().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("dockerhub list tags: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
			Next *string `json:"next"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("dockerhub list tags decode: %w", err)
		}
		for _, r := range page.Results {
			out = append(out, r.Name)
		}
		if page.Next == nil || *page.Next == "" {
			break
		}
		next = *page.Next
	}
	return out, nil
}

// GetDigest resolves the manifest digest from the Registry HTTP API v2.
func (d *DockerHub) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	ns, repo := d.parseRepo(repository)
	if ns == "" || repo == "" {
		return "", fmt.Errorf("dockerhub: invalid repository %q", repository)
	}
	token, err := d.registryToken(ctx, ns, repo)
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("%s/v2/%s/%s/manifests/%s", d.regBase(), url.PathEscape(ns), url.PathEscape(repo), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("dockerhub registry manifest: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("dockerhub: missing Docker-Content-Digest header")
	}
	return digest, nil
}

func (d *DockerHub) registryToken(ctx context.Context, namespace, repo string) (string, error) {
	u, err := url.Parse(d.authBase() + "/token")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("service", "registry.docker.io")
	q.Set("scope", fmt.Sprintf("repository:%s/%s:pull", namespace, repo))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	if d.creds.Username != "" {
		req.SetBasicAuth(d.creds.Username, d.creds.Password)
	}
	resp, err := d.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("dockerhub auth token: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("dockerhub auth token decode: %w", err)
	}
	if tok.Token == "" {
		return "", fmt.Errorf("dockerhub: empty registry token")
	}
	return tok.Token, nil
}
