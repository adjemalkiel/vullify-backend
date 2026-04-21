package registry

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNewConnector_GHCR(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(GHCRCredentials{GitHubToken: "ghp_test"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConnector(TypeGHCR, raw)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := c.(*GHCR)
	if !ok {
		t.Fatalf("expected *GHCR, got %T", c)
	}
	if g.regBase() == "" {
		t.Fatal("empty reg base")
	}
}

func TestGHCR_ListRepositories_Empty(t *testing.T) {
	t.Parallel()
	g := NewGHCR(GHCRCredentials{GitHubToken: "x"})
	repos, err := g.ListRepositories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 {
		t.Fatalf("expected empty repos, got %d", len(repos))
	}
}
