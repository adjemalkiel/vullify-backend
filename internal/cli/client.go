package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client calls the Vullify REST API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func newClient() *Client {
	return &Client{
		BaseURL: strings.TrimRight(serverURL, "/"),
		Token:   apiToken,
		HTTP: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) authHeader(req *http.Request) {
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.Token))
	}
}

type envelope struct {
	Data json.RawMessage `json:"data"`
	Meta *struct {
		Page    int   `json:"page"`
		PerPage int   `json:"per_page"`
		Total   int64 `json:"total"`
	} `json:"meta"`
}

type apiErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// CreateScanByRef POST /api/v1/scans with image_ref.
func (c *Client) CreateScanByRef(ctx context.Context, imageRef string) (string, error) {
	body, err := json.Marshal(map[string]string{"image_ref": strings.TrimSpace(imageRef)})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/scans", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c.authHeader(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", parseAPIError(resp.StatusCode, raw)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("decode envelope: %w", err)
	}
	var scan struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Data, &scan); err != nil {
		return "", fmt.Errorf("decode scan: %w", err)
	}
	if scan.ID == "" {
		return "", fmt.Errorf("empty scan id in response")
	}
	return scan.ID, nil
}

// GetScan GET /api/v1/scans/:id
func (c *Client) GetScan(ctx context.Context, scanID string) (map[string]any, error) {
	u := c.BaseURL + "/api/v1/scans/" + url.PathEscape(scanID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.authHeader(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseAPIError(resp.StatusCode, raw)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(env.Data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Finding is one vulnerability row from the API.
type Finding struct {
	ID                string `json:"id"`
	VulnerabilityID   string `json:"vulnerability_id"`
	PackageName       string `json:"package_name"`
	Severity          string `json:"severity"`
	InstalledVersion  string `json:"installed_version,omitempty"`
	FixedVersion      string `json:"fixed_version,omitempty"`
	Title             string `json:"title,omitempty"`
}

// ListAllFindings paginates GET /api/v1/scans/:id/findings.
func (c *Client) ListAllFindings(ctx context.Context, scanID string) ([]Finding, error) {
	const perPage = 100
	var all []Finding
	page := 1
	for {
		u, err := url.Parse(c.BaseURL + "/api/v1/scans/" + url.PathEscape(scanID) + "/findings")
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", perPage))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		c.authHeader(req)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, parseAPIError(resp.StatusCode, raw)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, err
		}
		var batch []Finding
		if err := json.Unmarshal(env.Data, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) == 0 {
			break
		}
		if env.Meta == nil || len(batch) < perPage || int64(len(all)) >= env.Meta.Total {
			break
		}
		page++
		if page > 10000 {
			break
		}
	}
	return all, nil
}

// GetSBOM GET /api/v1/scans/:id/sbom (raw JSON body, not envelope).
func (c *Client) GetSBOM(ctx context.Context, scanID string) ([]byte, string, error) {
	u := c.BaseURL + "/api/v1/scans/" + url.PathEscape(scanID) + "/sbom"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	c.authHeader(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", parseAPIError(resp.StatusCode, raw)
	}
	format := resp.Header.Get("X-SBOM-Format")
	return raw, format, nil
}

func parseAPIError(status int, body []byte) error {
	var e apiErrorBody
	if json.Unmarshal(body, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("api %d: %s (%s)", status, e.Error.Message, e.Error.Code)
	}
	return fmt.Errorf("api %d: %s", status, strings.TrimSpace(string(body)))
}
