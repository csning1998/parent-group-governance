package gitlabapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// recordedRequest captures inbound HTTP request attributes for verification.
type recordedRequest struct {
	method string
	path   string
	form   url.Values
	token  string
}

// newRecordingServer starts a test HTTP server capturing inbound requests and answering PUT with putStatus.
func newRecordingServer(t *testing.T, putStatus int) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var requests []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, recordedRequest{method: r.Method, path: r.URL.EscapedPath(), form: r.PostForm, token: r.Header.Get("PRIVATE-TOKEN")})
		if r.Method == http.MethodPut {
			w.WriteHeader(putStatus)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

// TestUpsertGroupVariable asserts the update of an existing variable, the creation after a 404, and a rejection whose error omits the value.
func TestUpsertGroupVariable(t *testing.T) {
	variable := Variable{Key: "SONAR_TOKEN", Value: "secret-value", Masked: true, Hidden: true, Raw: true}
	const putPath = "PUT /api/v4/groups/42/variables/SONAR_TOKEN"
	cases := map[string]struct {
		putStatus    int
		wantRequests []string
		wantErr      string
		checkForm    func(t *testing.T, form url.Values)
	}{
		"an existing variable is updated without masked_and_hidden": {
			putStatus:    http.StatusOK,
			wantRequests: []string{putPath},
			checkForm: func(t *testing.T, form url.Values) {
				if form.Get("value") != "secret-value" || form.Get("raw") != "true" || form.Get("protected") != "false" || form.Has("masked_and_hidden") {
					t.Fatalf("the PUT carries form %v", form)
				}
			},
		},
		"a missing variable is created as masked and hidden": {
			putStatus:    http.StatusNotFound,
			wantRequests: []string{putPath, "POST /api/v4/groups/42/variables"},
			checkForm: func(t *testing.T, form url.Values) {
				if form.Get("key") != "SONAR_TOKEN" || form.Get("masked_and_hidden") != "true" || form.Has("masked") {
					t.Fatalf("the POST carries form %v, want key and masked_and_hidden without masked", form)
				}
			},
		},
		"a rejection reports the status without the value": {
			putStatus:    http.StatusForbidden,
			wantRequests: []string{putPath},
			wantErr:      "403",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, requests := newRecordingServer(t, tc.putStatus)
			err := New(srv.URL+"/api/v4/", "pat").UpsertGroupVariable(context.Background(), "42", variable)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatal(err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("got %v, want an error carrying %q", err, tc.wantErr)
			case err != nil && strings.Contains(err.Error(), variable.Value):
				t.Fatal("the error carries the variable value")
			}
			got := make([]string, len(*requests))
			for i, r := range *requests {
				if r.token != "pat" {
					t.Fatalf("request %d carries token %q", i, r.token)
				}
				got[i] = r.method + " " + r.path
			}
			if !slices.Equal(got, tc.wantRequests) {
				t.Fatalf("got requests %v, want %v", got, tc.wantRequests)
			}
			if tc.checkForm != nil {
				tc.checkForm(t, (*requests)[len(*requests)-1].form)
			}
		})
	}
}
