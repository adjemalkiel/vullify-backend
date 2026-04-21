package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDockerHub_TestConnection(t *testing.T) {
	t.Parallel()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/repositories/testns/" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("page_size"); got != "1" {
			t.Errorf("page_size: got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"count":0,"results":[],"next":null}`)
	}))
	t.Cleanup(hub.Close)

	dh := NewDockerHub(DockerHubCredentials{
		Username:  "user",
		Password:  "pass",
		Namespace: "testns",
	})
	dh.HubAPIURL = hub.URL

	if err := dh.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDockerHub_ListRepositories(t *testing.T) {
	t.Parallel()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/repositories/acme/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"results":[{"name":"web"}],"next":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(hub.Close)

	dh := NewDockerHub(DockerHubCredentials{Namespace: "acme"})
	dh.HubAPIURL = hub.URL

	repos, err := dh.ListRepositories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0] != "acme/web" {
		t.Fatalf("repos: %#v", repos)
	}
}

func TestDockerHub_ListTags(t *testing.T) {
	t.Parallel()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/repositories/acme/web/tags" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"results":[{"name":"v1.0"}],"next":null}`)
	}))
	t.Cleanup(hub.Close)

	dh := NewDockerHub(DockerHubCredentials{Namespace: "acme"})
	dh.HubAPIURL = hub.URL

	tags, err := dh.ListTags(context.Background(), "acme/web")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0] != "v1.0" {
		t.Fatalf("tags: %#v", tags)
	}
}

func TestDockerHub_GetDigest(t *testing.T) {
	t.Parallel()

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/token") {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("service"); got != "registry.docker.io" {
			t.Errorf("service: %q", got)
		}
		scope := r.URL.Query().Get("scope")
		if scope != "repository:acme/web:pull" {
			t.Errorf("scope: %q", scope)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "user" || p != "secret" {
			t.Errorf("basic auth: ok=%v user=%q", ok, u)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"registry-token"}`)
	}))
	t.Cleanup(auth.Close)

	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		expected := "/v2/acme/web/manifests/v1.0"
		if r.URL.Path != expected {
			t.Errorf("path: got %q want %q", r.URL.Path, expected)
		}
		if r.Header.Get("Authorization") != "Bearer registry-token" {
			t.Errorf("Authorization: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/vnd.docker.distribution.manifest.v2+json" {
			t.Errorf("Accept: %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(reg.Close)

	dh := NewDockerHub(DockerHubCredentials{
		Username:  "user",
		Password:  "secret",
		Namespace: "acme",
	})
	dh.AuthURL = auth.URL
	dh.RegistryURL = reg.URL

	digest, err := dh.GetDigest(context.Background(), "acme/web", "v1.0")
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:deadbeef" {
		t.Fatalf("digest: %q", digest)
	}
}

func TestNewConnector_Unsupported(t *testing.T) {
	t.Parallel()
	_, err := NewConnector("unknown", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
