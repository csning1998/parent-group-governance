package sonarusertokens

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServer starts a mock SonarQube HTTP server validating basic authentication credentials.
func newServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if login, password, ok := r.BasicAuth(); !ok || login != "admin" || password != "admin-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/api/user_tokens/", "admin", "admin-password")
}

// TestGenerate asserts the name and type sent by Client.Generate, and the error upon a response without a token.
func TestGenerate(t *testing.T) {
	t.Run("returns the token", func(t *testing.T) {
		c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/user_tokens/generate" {
				t.Fatalf("got %s %s, want POST /api/user_tokens/generate", r.Method, r.URL.Path)
			}
			if r.FormValue("name") != "gitlab-ci-analysis-20261111T000000Z" || r.FormValue("type") != "GLOBAL_ANALYSIS_TOKEN" {
				t.Fatalf("got name %q and type %q", r.FormValue("name"), r.FormValue("type"))
			}
			_, _ = w.Write([]byte(`{"login":"admin","name":"gitlab-ci-analysis-20261111T000000Z","token":"squ_issued","type":"GLOBAL_ANALYSIS_TOKEN"}`))
		})

		token, err := c.Generate(context.Background(), "gitlab-ci-analysis-20261111T000000Z", "GLOBAL_ANALYSIS_TOKEN")
		if err != nil {
			t.Fatal(err)
		}
		if token != "squ_issued" {
			t.Fatalf("got token %q, want squ_issued", token)
		}
	})

	t.Run("rejects a response without a token", func(t *testing.T) {
		c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"login":"admin","name":"gitlab-ci-analysis"}`))
		})

		if _, err := c.Generate(context.Background(), "gitlab-ci-analysis", "GLOBAL_ANALYSIS_TOKEN"); err == nil {
			t.Fatal("got no error for a response without a token")
		}
	})
}

// TestList asserts the names and types of every token returned by the search endpoint.
func TestList(t *testing.T) {
	c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/user_tokens/search" {
			t.Fatalf("got %s %s, want GET /api/user_tokens/search", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"login":"admin","userTokens":[{"name":"gitlab-ci-analysis","type":"GLOBAL_ANALYSIS_TOKEN"},{"name":"ide","type":"USER_TOKEN"}]}`))
	})

	tokens, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0] != (Token{Name: "gitlab-ci-analysis", Type: "GLOBAL_ANALYSIS_TOKEN"}) || tokens[1].Name != "ide" {
		t.Fatalf("got %v", tokens)
	}
}

// TestRevoke asserts token revocation by name and the status code in the error of a rejection.
func TestRevoke(t *testing.T) {
	t.Run("sends the name", func(t *testing.T) {
		var revoked string
		c := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/user_tokens/revoke" {
				t.Fatalf("got %s %s, want POST /api/user_tokens/revoke", r.Method, r.URL.Path)
			}
			revoked = r.FormValue("name")
			w.WriteHeader(http.StatusNoContent)
		})

		if err := c.Revoke(context.Background(), "gitlab-ci-analysis"); err != nil {
			t.Fatal(err)
		}
		if revoked != "gitlab-ci-analysis" {
			t.Fatalf("revoked %q, want gitlab-ci-analysis", revoked)
		}
	})

	t.Run("reports the status of a rejection", func(t *testing.T) {
		c := newServer(t, func(w http.ResponseWriter, r *http.Request) {})
		c.password = "wrong"

		err := c.Revoke(context.Background(), "gitlab-ci-analysis")
		if err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatalf("got %v, want an error carrying status 401", err)
		}
	})
}
