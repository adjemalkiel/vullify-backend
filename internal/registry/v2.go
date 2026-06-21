package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// V2Credentials configures a generic Docker Registry V2 connection and webhooks.
type V2Credentials struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	WebhookSecret string `json:"webhook_secret,omitempty"`
	RegistryURL   string `json:"registry_url,omitempty"`
}

// V2Registry implements RegistryConnector for any Docker Registry HTTP API V2 compliant registry
// (Harbor, JFrog, self-hosted, etc.) supporting Bearer token exchange and Basic auth.
type V2Registry struct {
	HTTPClient  *http.Client
	RegistryURL string

	mu       sync.Mutex
	token    *v2CachedToken
	creds    V2Credentials
}

type v2CachedToken struct {
	Token     string
	ExpiresAt time.Time
}

// NewV2Registry returns a generic V2 connector with production defaults.
func NewV2Registry(c V2Credentials, registryURL string) *V2Registry {
	return &V2Registry{
		HTTPClient:  http.DefaultClient,
		RegistryURL: strings.TrimRight(registryURL, "/"),
		creds:       c,
	}
}

func (v *V2Registry) client() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return http.DefaultClient
}

func (v *V2Registry) regBase() string {
	if v.RegistryURL != "" {
		return strings.TrimRight(v.RegistryURL, "/")
	}
	return ""
}

// basicAuthHeader returns the Basic auth value if username and password are set.
func (v *V2Registry) basicAuthHeader() string {
	u := strings.TrimSpace(v.creds.Username)
	p := v.creds.Password
	if u == "" || p == "" {
		return ""
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

// authHeaders returns request headers for authenticating to the registry.
// It tries Bearer token first, then falls back to Basic auth.
func (v *V2Registry) authHeaders(ctx context.Context) (map[string]string, error) {
	headers := make(map[string]string)

	// Try Bearer token first (requires successful token negotiation).
	token, err := v.getBearerToken(ctx)
	if err == nil && token != "" {
		headers["Authorization"] = "Bearer " + token
		return headers, nil
	}

	// Fall back to Basic auth.
	basic := v.basicAuthHeader()
	if basic != "" {
		headers["Authorization"] = basic
		return headers, nil
	}

	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("v2: no authentication method available (provide username/password)")
}

// getBearerToken returns a cached Bearer token or negotiates a new one.
func (v *V2Registry) getBearerToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	if v.token != nil && time.Now().Before(v.token.ExpiresAt) {
		tok := v.token.Token
		v.mu.Unlock()
		return tok, nil
	}
	v.mu.Unlock()

	tok, err := v.negotiateToken(ctx)
	if err != nil {
		return "", err
	}

	v.mu.Lock()
	v.token = tok
	v.mu.Unlock()
	return tok.Token, nil
}

// negotiateToken probes /v2/ with Basic auth (or unauthenticated) and follows the
// Www-Authenticate Bearer challenge to obtain a token.
func (v *V2Registry) negotiateToken(ctx context.Context) (*v2CachedToken, error) {
	cli := v.client()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.regBase()+"/v2/", nil)
	if err != nil {
		return nil, err
	}

	// Always send Basic auth on the probe so registries don't just return 401 with an
	// opaque token endpoint that requires client credentials. If the registry returns
	// a Bearer challenge, we'll use that instead.
	basic := v.basicAuthHeader()
	if basic != "" {
		req.Header.Set("Authorization", basic)
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("v2 probe: %w", err)
	}
	defer resp.Body.Close()

	// If we got 200 with Basic auth, no Bearer token needed.
	if resp.StatusCode == http.StatusOK {
		return nil, fmt.Errorf("v2: bearer token not available; use basic auth")
	}

	// If 401, look for Bearer challenge.
	if resp.StatusCode != http.StatusUnauthorized {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("v2 probe: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	challenge := parseWwwAuthenticate(resp.Header.Get("Www-Authenticate"))
	if challenge.Realm == "" {
		return nil, fmt.Errorf("v2: no Bearer Www-Authenticate challenge received")
	}

	// Build token URL with service and scope.
	tokenURL, err := url.Parse(challenge.Realm)
	if err != nil {
		return nil, fmt.Errorf("v2 bad token realm: %w", err)
	}
	q := tokenURL.Query()
	if challenge.Service != "" {
		q.Set("service", challenge.Service)
	}
	// Request a broad scope if the challenge didn't specify one.
	if challenge.Scope == "" {
		q.Set("scope", "repository:*:*")
	} else {
		q.Set("scope", challenge.Scope)
	}
	tokenURL.RawQuery = q.Encode()

	tokReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if basic != "" {
		tokReq.Header.Set("Authorization", basic)
	}
	tokResp, err := cli.Do(tokReq)
	if err != nil {
		return nil, fmt.Errorf("v2 token exchange: %w", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode < 200 || tokResp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(tokResp.Body, 2048))
		return nil, fmt.Errorf("v2 token exchange: %s: %s", tokResp.Status, strings.TrimSpace(string(b)))
	}

	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("v2 token decode: %w", err)
	}
	tokVal := result.Token
	if tokVal == "" {
		tokVal = result.AccessToken
	}
	if tokVal == "" {
		return nil, fmt.Errorf("v2 token: empty token in response")
	}

	ttl := time.Duration(result.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 50 * time.Minute
	}

	return &v2CachedToken{
		Token:     tokVal,
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

// bearerChallenge holds parsed Www-Authenticate Bearer parameters.
type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

// parseWwwAuthenticate extracts Bearer challenge parameters from the header value.
func parseWwwAuthenticate(header string) bearerChallenge {
	var c bearerChallenge
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return c
	}
	rest := header[len("bearer "):]
	for _, part := range splitAuthParams(rest) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			val := strings.Trim(kv[1], `"`)
			switch strings.ToLower(strings.TrimSpace(kv[0])) {
			case "realm":
				c.Realm = val
			case "service":
				c.Service = val
			case "scope":
				c.Scope = val
			}
		}
	}
	return c
}

// splitAuthParams splits a Www-Authenticate parameter string on commas outside quotes.
func splitAuthParams(s string) []string {
	var parts []string
	start := 0
	quoted := false
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			quoted = !quoted
		}
		if s[i] == ',' && !quoted {
			parts = append(parts, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, strings.TrimSpace(s[start:]))
	}
	return parts
}

// TestConnection verifies the registry root endpoint with the best available auth.
func (v *V2Registry) TestConnection(ctx context.Context) error {
	if strings.TrimSpace(v.creds.Username) == "" || v.creds.Password == "" {
		return fmt.Errorf("v2: username and password are required")
	}
	cli := v.client()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.regBase()+"/v2/", nil)
	if err != nil {
		return err
	}
	headers, err := v.authHeaders(ctx)
	if err != nil {
		return err
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("v2 registry: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// ListRepositories paginates the V2 _catalog endpoint.
func (v *V2Registry) ListRepositories(ctx context.Context) ([]string, error) {
	headers, err := v.authHeaders(ctx)
	if err != nil {
		return nil, err
	}
	cli := v.client()
	var all []string
	next := v.regBase() + "/v2/_catalog?n=100"
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		for k, val := range headers {
			req.Header.Set(k, val)
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
			return nil, fmt.Errorf("v2 catalog: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("v2 catalog decode: %w", err)
		}
		all = append(all, page.Repositories...)
		next = nextCatalogURL(resp.Header.Get("Link"), v.regBase())
	}
	sort.Strings(all)
	return all, nil
}

// ListTags lists tags via /v2/{repo}/tags/list with Link header pagination.
func (v *V2Registry) ListTags(ctx context.Context, repository string) ([]string, error) {
	headers, err := v.authHeaders(ctx)
	if err != nil {
		return nil, err
	}
	cli := v.client()
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, fmt.Errorf("v2: empty repository")
	}
	u := v.regBase() + "/v2/" + encodeRepoPath(repository) + "/tags/list"

	var names []string
	for u != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		for k, val := range headers {
			req.Header.Set(k, val)
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
			return nil, fmt.Errorf("v2 tags list: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("v2 tags decode: %w", err)
		}
		names = append(names, page.Tags...)
		next := nextCatalogURL(resp.Header.Get("Link"), v.regBase())
		if next == "" {
			break
		}
		u = next
	}
	sort.Strings(names)
	return names, nil
}

// GetDigest resolves digest via HEAD /v2/{repo}/manifests/{tag}.
func (v *V2Registry) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	headers, err := v.authHeaders(ctx)
	if err != nil {
		return "", err
	}
	cli := v.client()
	if repository == "" || tag == "" {
		return "", fmt.Errorf("v2: repository and tag required")
	}
	path := fmt.Sprintf("%s/v2/%s/manifests/%s", v.regBase(), encodeRepoPath(repository), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, path, nil)
	if err != nil {
		return "", err
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("v2 manifest: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("v2: missing Docker-Content-Digest header")
	}
	return digest, nil
}
