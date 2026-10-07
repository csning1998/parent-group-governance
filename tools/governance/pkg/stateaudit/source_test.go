package stateaudit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeLayer(t *testing.T, layersDir, name, content string) {
	t.Helper()
	dir := filepath.Join(layersDir, name)
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	if content == "" {
		return
	}
	err = os.WriteFile(filepath.Join(dir, "providers.tf"), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestDiscoverLayers(t *testing.T) {
	layersDir := t.TempDir()
	writeLayer(t, layersDir, "group-topology", `terraform {
  backend "http" {
    address        = "https://gitlab.com/api/v4/projects/1/terraform/state/group-topology"
    lock_address   = "https://gitlab.com/api/v4/projects/1/terraform/state/group-topology/lock"
    lock_method    = "POST"
  }
}
`)
	writeLayer(t, layersDir, "group-foundation", "terraform {\n  backend \"http\" {\n    address = \"https://gitlab.com/api/v4/projects/1/terraform/state/group-foundation\"\n  }\n}\n")
	writeLayer(t, layersDir, "local-only", "terraform {\n  backend \"local\" {}\n}\n")
	writeLayer(t, layersDir, "empty", "")

	got, err := DiscoverLayers(layersDir)
	want := []Layer{
		{Name: "group-foundation", Address: "https://gitlab.com/api/v4/projects/1/terraform/state/group-foundation"},
		{Name: "group-topology", Address: "https://gitlab.com/api/v4/projects/1/terraform/state/group-topology"},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("DiscoverLayers = %+v, %v, want %+v", got, err, want)
	}
}

func TestDiscoverLayersRejectsInvalidBackend(t *testing.T) {
	for name, content := range map[string]string{
		"syntax error":    "terraform {\n",
		"computed":        "terraform {\n  backend \"http\" {\n    address = local.base\n  }\n}\n",
		"missing address": "terraform {\n  backend \"http\" {\n    lock_method = \"POST\"\n  }\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			layersDir := t.TempDir()
			writeLayer(t, layersDir, "broken", content)
			_, err := DiscoverLayers(layersDir)
			if err == nil || !strings.Contains(err.Error(), "broken") {
				t.Errorf("DiscoverLayers error = %v, want an error which names the layer", err)
			}
		})
	}
}

// newBackend serves the current state, serial 2, and a 404 for every other version, behind basic authentication.
func newBackend(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "gitlab-ci-token" || password != "backend-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/state/a":
			_, _ = w.Write([]byte(`{"version": 4, "serial": 3}`))
		case "/state/never-applied":
			w.WriteHeader(http.StatusNoContent)
		case "/state/a/versions/2":
			_, _ = w.Write([]byte(`{"version": 4, "serial": 2}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestHTTPSource(t *testing.T) {
	server := newBackend(t)
	source := HTTPSource{Client: server.Client(), Username: "gitlab-ci-token", Password: "backend-secret"}

	current, err := source.FetchCurrent(context.Background(), server.URL+"/state/a")
	if err != nil || string(current) != `{"version": 4, "serial": 3}` {
		t.Errorf("FetchCurrent = %q, %v", current, err)
	}
	version, err := source.FetchVersion(context.Background(), server.URL+"/state/a", 2)
	if err != nil || string(version) != `{"version": 4, "serial": 2}` {
		t.Errorf("FetchVersion(2) = %q, %v", version, err)
	}
	_, err = source.FetchVersion(context.Background(), server.URL+"/state/a", 1)
	if !errors.Is(err, ErrVersionMissing) {
		t.Errorf("FetchVersion(1) error = %v, want ErrVersionMissing", err)
	}
}

func TestHTTPSourceReportsRejectedCredentials(t *testing.T) {
	server := newBackend(t)
	source := HTTPSource{Client: server.Client(), Username: "gitlab-ci-token", Password: "wrong-secret"}

	_, err := source.FetchCurrent(context.Background(), server.URL+"/state/a")
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong-secret") {
		t.Errorf("FetchCurrent error = %v, want the status 401 without the password", err)
	}
}

// TestHTTPSourceReportsAStateWhichNeverExisted covers GitLab, which answers 204 for a layer without any apply.
func TestHTTPSourceReportsAStateWhichNeverExisted(t *testing.T) {
	server := newBackend(t)
	source := HTTPSource{Client: server.Client(), Username: "gitlab-ci-token", Password: "backend-secret"}

	_, err := source.FetchCurrent(context.Background(), server.URL+"/state/never-applied")
	if !errors.Is(err, ErrStateMissing) {
		t.Errorf("FetchCurrent error = %v, want ErrStateMissing", err)
	}
}
