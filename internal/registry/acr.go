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
	"sync"
	"time"
)

// ACRCredentials configures Azure Container Registry access via service principal.
type ACRCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TenantID     string `json:"tenant_id"`
	RegistryName string `json:"registry_name"`
}

// ACR implements RegistryConnector for Azure Container Registry using service principal
// OAuth2 token exchange (AAD token → ACR refresh token → ACR access token).
type ACR struct {
	HTTPClient  *http.Client
	RegistryURL string // derived from RegistryName as https://{name}.azurecr.io

	mu       sync.Mutex
	token    *acrCachedToken
	creds    ACRCredentials
}

type acrCachedToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

// NewACR returns an ACR connector with production defaults.
func NewACR(c ACRCredentials) *ACR {
	return &ACR{
		HTTPClient:  http.DefaultClient,
		RegistryURL: fmt.Sprintf("https://%s.azurecr.io", strings.TrimSpace(c.RegistryName)),
		creds:       c,
	}
}

func (a *ACR) client() *http.Client {
	if a.HTTPClient != nil {
		return a.HTTPClient
	}
	return http.DefaultClient
}

func (a *ACR) regBase() string {
	if a.RegistryURL != "" {
		return strings.TrimRight(a.RegistryURL, "/")
	}
	return fmt.Sprintf("https://%s.azurecr.io", strings.TrimSpace(a.creds.RegistryName))
}

func (a *ACR) loginURL() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(a.creds.TenantID))
}

func (a *ACR) exchangeURL() string {
	return a.regBase() + "/oauth2/exchange"
}

// getACRToken acquires a cached or fresh ACR access token via the AAD→ACR OAuth2 flow.
func (a *ACR) getACRToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	if a.token != nil && time.Now().Before(a.token.ExpiresAt) {
		tok := a.token.AccessToken
		a.mu.Unlock()
		return tok, nil
	}
	a.mu.Unlock()

	tok, err := a.resolveACRToken(ctx)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	a.token = tok
	a.mu.Unlock()
	return tok.AccessToken, nil
}

// resolveACRToken performs the full AAD → ACR token exchange flow.
func (a *ACR) resolveACRToken(ctx context.Context) (*acrCachedToken, error) {
	cli := a.client()

	// Step 1: Get AAD token via client_credentials grant.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {a.creds.ClientID},
		"client_secret": {a.creds.ClientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}
	aadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.loginURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	aadReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	aadResp, err := cli.Do(aadReq)
	if err != nil {
		return nil, fmt.Errorf("acr aad token: %w", err)
	}
	defer aadResp.Body.Close()
	if aadResp.StatusCode < 200 || aadResp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(aadResp.Body, 2048))
		return nil, fmt.Errorf("acr aad token: %s: %s", aadResp.Status, strings.TrimSpace(string(b)))
	}

	var aadResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(aadResp.Body).Decode(&aadResult); err != nil {
		return nil, fmt.Errorf("acr aad token decode: %w", err)
	}
	if aadResult.AccessToken == "" {
		return nil, fmt.Errorf("acr aad token: empty access_token in response")
	}

	// Step 2: Exchange AAD token for ACR refresh token.
	exchangeForm := url.Values{
		"grant_type":   {"access_token"},
		"service":      {a.creds.RegistryName},
		"access_token": {aadResult.AccessToken},
	}
	exReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.exchangeURL(), strings.NewReader(exchangeForm.Encode()))
	if err != nil {
		return nil, err
	}
	exReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exResp, err := cli.Do(exReq)
	if err != nil {
		return nil, fmt.Errorf("acr exchange: %w", err)
	}
	defer exResp.Body.Close()
	if exResp.StatusCode < 200 || exResp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(exResp.Body, 2048))
		return nil, fmt.Errorf("acr exchange: %s: %s", exResp.Status, strings.TrimSpace(string(b)))
	}

	var exResult struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(exResp.Body).Decode(&exResult); err != nil {
		return nil, fmt.Errorf("acr exchange decode: %w", err)
	}
	if exResult.RefreshToken == "" {
		return nil, fmt.Errorf("acr exchange: empty refresh_token in response")
	}

	// Step 3: Exchange refresh token for ACR access token.
	accessForm := url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {a.creds.RegistryName},
		"refresh_token": {exResult.RefreshToken},
		"scope":         {"repository:*:*"},
	}
	accessReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.exchangeURL(), strings.NewReader(accessForm.Encode()))
	if err != nil {
		return nil, err
	}
	accessReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accessResp, err := cli.Do(accessReq)
	if err != nil {
		return nil, fmt.Errorf("acr access token: %w", err)
	}
	defer accessResp.Body.Close()
	if accessResp.StatusCode < 200 || accessResp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(accessResp.Body, 2048))
		return nil, fmt.Errorf("acr access token: %s: %s", accessResp.Status, strings.TrimSpace(string(b)))
	}

	var accessResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(accessResp.Body).Decode(&accessResult); err != nil {
		return nil, fmt.Errorf("acr access token decode: %w", err)
	}
	if accessResult.AccessToken == "" {
		return nil, fmt.Errorf("acr access token: empty access_token in response")
	}

	return &acrCachedToken{
		AccessToken: accessResult.AccessToken,
		ExpiresAt:   time.Now().Add(50 * time.Minute),
	}, nil
}

// TestConnection verifies the full OAuth2 token exchange flow succeeds.
func (a *ACR) TestConnection(ctx context.Context) error {
	if strings.TrimSpace(a.creds.ClientID) == "" ||
		strings.TrimSpace(a.creds.ClientSecret) == "" ||
		strings.TrimSpace(a.creds.TenantID) == "" ||
		strings.TrimSpace(a.creds.RegistryName) == "" {
		return fmt.Errorf("acr: client_id, client_secret, tenant_id, and registry_name are required")
	}
	_, err := a.getACRToken(ctx)
	return err
}

// ListRepositories paginates the V2 _catalog endpoint.
func (a *ACR) ListRepositories(ctx context.Context) ([]string, error) {
	token, err := a.getACRToken(ctx)
	if err != nil {
		return nil, err
	}
	cli := a.client()
	var all []string
	next := a.regBase() + "/v2/_catalog?n=100"
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
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
			return nil, fmt.Errorf("acr catalog: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("acr catalog decode: %w", err)
		}
		all = append(all, page.Repositories...)
		next = nextCatalogURL(resp.Header.Get("Link"), a.regBase())
	}
	sort.Strings(all)
	return all, nil
}

// ListTags lists tags via /v2/{repo}/tags/list with Link header pagination.
func (a *ACR) ListTags(ctx context.Context, repository string) ([]string, error) {
	token, err := a.getACRToken(ctx)
	if err != nil {
		return nil, err
	}
	cli := a.client()
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return nil, fmt.Errorf("acr: empty repository")
	}
	u := a.regBase() + "/v2/" + encodeRepoPath(repository) + "/tags/list"

	var names []string
	for u != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
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
			return nil, fmt.Errorf("acr tags list: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var page struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("acr tags decode: %w", err)
		}
		names = append(names, page.Tags...)
		next := nextCatalogURL(resp.Header.Get("Link"), a.regBase())
		if next == "" {
			break
		}
		u = next
	}
	sort.Strings(names)
	return names, nil
}

// GetDigest resolves digest via HEAD /v2/{repo}/manifests/{tag}.
func (a *ACR) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	token, err := a.getACRToken(ctx)
	if err != nil {
		return "", err
	}
	cli := a.client()
	if repository == "" || tag == "" {
		return "", fmt.Errorf("acr: repository and tag required")
	}
	path := fmt.Sprintf("%s/v2/%s/manifests/%s", a.regBase(), encodeRepoPath(repository), url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("acr manifest: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("acr: missing Docker-Content-Digest header")
	}
	return digest, nil
}
