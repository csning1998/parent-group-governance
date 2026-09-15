package httprotate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

func TestFormSpecDeploySendsFixedFieldNames(t *testing.T) {
	var gotLogin, gotPassword, gotPrevious, gotAuthUser, gotAuthPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotLogin = r.PostForm.Get("login")
		gotPassword = r.PostForm.Get("password")
		gotPrevious = r.PostForm.Get("previousPassword")
		gotAuthUser, gotAuthPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	spec := FormSpec{URL: srv.URL, Login: "admin"}
	if err := spec.Deploy(context.Background(), "old-pass", "new-pass"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if gotLogin != "admin" {
		t.Errorf("login field = %q, want admin", gotLogin)
	}
	if gotPassword != "new-pass" {
		t.Errorf("password field = %q, want new-pass", gotPassword)
	}
	if gotPrevious != "old-pass" {
		t.Errorf("previousPassword field = %q, want old-pass", gotPrevious)
	}
	if gotAuthUser != "admin" || gotAuthPass != "old-pass" {
		t.Errorf("basic auth = %q:%q, want admin:old-pass", gotAuthUser, gotAuthPass)
	}
}

func TestFormSpecDeployNonSuccessStatus(t *testing.T) {
	cases := []struct {
		name             string
		statusCode       int
		body             string
		wantUnauthorized bool
	}{
		{"401 marks ErrUnauthorized", http.StatusUnauthorized, "bad credentials", true},
		{"400 is a plain failure", http.StatusBadRequest, "policy violation", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.statusCode)
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()

			spec := FormSpec{URL: srv.URL, Login: "admin"}
			err := spec.Deploy(context.Background(), "wrong-pass", "new-pass")
			if err == nil {
				t.Fatal("Deploy: want error, got nil")
			}
			if got := errors.Is(err, ErrUnauthorized); got != c.wantUnauthorized {
				t.Errorf("errors.Is(err, ErrUnauthorized) = %v, want %v", got, c.wantUnauthorized)
			}
			if got := errors.Is(err, secretrotate.ErrAuthRejected); got != c.wantUnauthorized {
				t.Errorf("errors.Is(err, secretrotate.ErrAuthRejected) = %v, want %v", got, c.wantUnauthorized)
			}
			if !strings.Contains(err.Error(), c.body) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), c.body)
			}
		})
	}
}

func TestFormSpecDeployConnectionRefused(t *testing.T) {
	spec := FormSpec{URL: "http://127.0.0.1:1", Login: "admin"}
	err := spec.Deploy(context.Background(), "old-pass", "new-pass")
	if err == nil {
		t.Fatal("Deploy: want error, got nil")
	}
	if !strings.Contains(err.Error(), "call") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "call")
	}
}

// TestFormSpecDeployDropsCredentialsOnCrossHostRedirect covers a compromised or misconfigured
// endpoint redirecting the request elsewhere. Basic Auth credentials MUST NOT follow a redirect
// to a different host.
func TestFormSpecDeployDropsCredentialsOnCrossHostRedirect(t *testing.T) {
	leaked := false
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			leaked = true
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer attacker.Close()

	legit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	defer legit.Close()

	spec := FormSpec{URL: legit.URL, Login: "admin"}
	_ = spec.Deploy(context.Background(), "super-secret-previous", "new-pass")

	if leaked {
		t.Error("Basic Auth credentials reached a cross-host redirect target, want them dropped")
	}
}

// TestFormSpecDeployPreservesInjectionAttemptCharactersVerbatim covers a replacement value
// carrying CRLF and markup. Form encoding MUST transmit the raw bytes as one opaque field value,
// never as extra headers or extra form fields.
func TestFormSpecDeployPreservesInjectionAttemptCharactersVerbatim(t *testing.T) {
	const evil = "x\r\nSet-Cookie: pwned=1\r\n\r\n<script>alert(1)</script>&extra=1"
	var gotPassword string
	extraFieldSeen := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotPassword = r.PostForm.Get("password")
		if r.PostForm.Get("extra") != "" {
			extraFieldSeen = true
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	spec := FormSpec{URL: srv.URL, Login: "admin"}
	if err := spec.Deploy(context.Background(), "old-pass", evil); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if gotPassword != evil {
		t.Errorf("password field = %q, want the raw value %q preserved through form encoding", gotPassword, evil)
	}
	if extraFieldSeen {
		t.Error("an injected extra form field was parsed out of the password value, want it kept opaque")
	}
}
