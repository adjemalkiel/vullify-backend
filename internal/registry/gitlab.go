package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// GitLabCredentials configures GitLab Container Registry REST API access.
// ProjectID is required for listing repositories and tags under that project.
type GitLabCredentials struct {
	BaseURL   string `json:"base_url"`
	Token     string `json:"token"`
	ProjectID int    `json:"project_id"`
	// WebhookSecret must match the GitLab webhook "secret token" (X-Gitlab-Token).
	WebhookSecret string `json:"webhook_secret,omitempty"`
}

// GitLab implements RegistryConnector using GitLab Container Registry API (v4).
type GitLab struct {
	HTTPClient *http.Client
	creds      GitLabCredentials
}

// NewGitLab returns a connector for GitLab (self-managed or GitLab.com).
func NewGitLab(c GitLabCredentials) *GitLab {
	return &GitLab{
		HTTPClient: http.DefaultClient,
		creds:      c,
	}
}

func (g *GitLab) client() *http.Client {
	if g.HTTPClient != nil {
		return g.HTTPClient
	}
	return http.DefaultClient
}

func (g *GitLab) apiBase() string {
	b := strings.TrimSpace(g.creds.BaseURL)
	if b == "" {
		b = "https://gitlab.com"
	}
	return strings.TrimRight(b, "/") + "/api/v4"
}

func (g *GitLab) authHeader(req *http.Request) {
	req.Header.Set("PRIVATE-TOKEN", g.creds.Token)
}

// TestConnection calls the registry repositories endpoint for the project.
func (g *GitLab) TestConnection(ctx context.Context) error {
	if g.creds.ProjectID == 0 {
		return fmt.Errorf("gitlab: project_id required")
	}
	if g.creds.Token == "" {
		return fmt.Errorf("gitlab: token required")
	}
	u := fmt.Sprintf("%s/projects/%d/registry/repositories?page=1&per_page=1", g.apiBase(), g.creds.ProjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	g.authHeader(req)
	resp, err := g.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("gitlab: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// ListRepositories returns repository paths (location/path) visible to the token in the project.
func (g *GitLab) ListRepositories(ctx context.Context) ([]string, error) {
	if g.creds.ProjectID == 0 {
		return nil, fmt.Errorf("gitlab: project_id required")
	}
	var out []string
	page := 1
	for {
		u := fmt.Sprintf("%s/projects/%d/registry/repositories?page=%d&per_page=100", g.apiBase(), g.creds.ProjectID, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		g.authHeader(req)
		resp, err := g.client().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("gitlab list repositories: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var repos []struct {
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Path     string `json:"path"`
			Location string `json:"location"`
		}
		if err := json.Unmarshal(body, &repos); err != nil {
			return nil, fmt.Errorf("gitlab list repositories decode: %w", err)
		}
		if len(repos) == 0 {
			break
		}
		for _, r := range repos {
			name := r.Path
			if name == "" {
				name = r.Name
			}
			if name == "" && r.Location != "" {
				name = r.Location
			}
			if name != "" {
				out = append(out, name)
			}
		}
		page++
	}
	return out, nil
}

// ListTags lists tags for a repository name/path or numeric registry repository ID.
func (g *GitLab) ListTags(ctx context.Context, repository string) ([]string, error) {
	if g.creds.ProjectID == 0 {
		return nil, fmt.Errorf("gitlab: project_id required")
	}
	repoID, err := g.resolveRepositoryID(ctx, repository)
	if err != nil {
		return nil, err
	}
	var out []string
	page := 1
	for {
		u := fmt.Sprintf("%s/projects/%d/registry/repositories/%d/tags?page=%d&per_page=100", g.apiBase(), g.creds.ProjectID, repoID, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		g.authHeader(req)
		resp, err := g.client().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("gitlab list tags: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var tags []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &tags); err != nil {
			return nil, fmt.Errorf("gitlab list tags decode: %w", err)
		}
		if len(tags) == 0 {
			break
		}
		for _, t := range tags {
			out = append(out, t.Name)
		}
		if len(tags) < 100 {
			break
		}
		page++
	}
	return out, nil
}

func (g *GitLab) resolveRepositoryID(ctx context.Context, repository string) (int, error) {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return 0, fmt.Errorf("gitlab: empty repository")
	}
	if id, err := strconv.Atoi(repository); err == nil {
		return id, nil
	}
	repos, err := g.listRepositoriesRaw(ctx)
	if err != nil {
		return 0, err
	}
	for _, r := range repos {
		if r.Path == repository || r.Name == repository || r.Location == repository {
			return r.ID, nil
		}
	}
	return 0, fmt.Errorf("gitlab: repository not found: %s", repository)
}

func (g *GitLab) listRepositoriesRaw(ctx context.Context) ([]struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Location string `json:"location"`
}, error) {
	var all []struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Path     string `json:"path"`
		Location string `json:"location"`
	}
	page := 1
	for {
		u := fmt.Sprintf("%s/projects/%d/registry/repositories?page=%d&per_page=100", g.apiBase(), g.creds.ProjectID, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		g.authHeader(req)
		resp, err := g.client().Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("gitlab list repositories: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var repos []struct {
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Path     string `json:"path"`
			Location string `json:"location"`
		}
		if err := json.Unmarshal(body, &repos); err != nil {
			return nil, err
		}
		if len(repos) == 0 {
			break
		}
		all = append(all, repos...)
		page++
	}
	return all, nil
}

// GetDigest returns the image digest for a tag when exposed by the GitLab tags API.
func (g *GitLab) GetDigest(ctx context.Context, repository, tag string) (string, error) {
	if g.creds.ProjectID == 0 {
		return "", fmt.Errorf("gitlab: project_id required")
	}
	repoID, err := g.resolveRepositoryID(ctx, repository)
	if err != nil {
		return "", err
	}
	page := 1
	for {
		u := fmt.Sprintf("%s/projects/%d/registry/repositories/%d/tags?page=%d&per_page=100", g.apiBase(), g.creds.ProjectID, repoID, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		g.authHeader(req)
		resp, err := g.client().Do(req)
		if err != nil {
			return "", err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("gitlab tags: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var tags []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		}
		if err := json.Unmarshal(body, &tags); err != nil {
			return "", fmt.Errorf("gitlab tags decode: %w", err)
		}
		if len(tags) == 0 {
			break
		}
		for _, t := range tags {
			if t.Name == tag && t.Digest != "" {
				return t.Digest, nil
			}
		}
		if len(tags) < 100 {
			break
		}
		page++
	}
	return "", fmt.Errorf("gitlab: digest not found for tag %q (API may omit digest for this GitLab version)", tag)
}
