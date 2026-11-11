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
			checkForm:    checkUpdateForm,
		},
		"a missing variable is created as masked and hidden": {
			putStatus:    http.StatusNotFound,
			wantRequests: []string{putPath, "POST /api/v4/groups/42/variables"},
			checkForm:    checkCreateForm,
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
			assertUpsertError(t, err, tc.wantErr, variable.Value)
			assertRecordedRequests(t, *requests, tc.wantRequests)
			if tc.checkForm != nil {
				tc.checkForm(t, (*requests)[len(*requests)-1].form)
			}
		})
	}
}

func checkUpdateForm(t *testing.T, form url.Values) {
	t.Helper()
	if form.Get("value") != "secret-value" || form.Get("raw") != "true" || form.Get("protected") != "false" || form.Has("masked_and_hidden") {
		t.Fatalf("the PUT carries form %v", form)
	}
}

func checkCreateForm(t *testing.T, form url.Values) {
	t.Helper()
	if form.Get("key") != "SONAR_TOKEN" || form.Get("masked_and_hidden") != "true" || form.Has("masked") {
		t.Fatalf("the POST carries form %v, want key and masked_and_hidden without masked", form)
	}
}

func assertUpsertError(t *testing.T, err error, want, secret string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatal(err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Fatalf("got %v, want an error carrying %q", err, want)
	case err != nil && strings.Contains(err.Error(), secret):
		t.Fatal("the error carries the variable value")
	}
}

func assertRecordedRequests(t *testing.T, requests []recordedRequest, want []string) {
	t.Helper()
	got := make([]string, len(requests))
	for i, r := range requests {
		if r.token != "pat" {
			t.Fatalf("request %d carries token %q", i, r.token)
		}
		got[i] = r.method + " " + r.path
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got requests %v, want %v", got, want)
	}
}

// TestUpsertProjectVariable asserts the escaped project path in the variable endpoint.
func TestUpsertProjectVariable(t *testing.T) {
	srv, requests := newRecordingServer(t, http.StatusOK)

	err := New(srv.URL, "pat").UpsertProjectVariable(context.Background(), "csning1998-lab/parent-group-governance", Variable{Key: "TAG_PUSH_TOKEN", Value: "tag-token"})
	if err != nil {
		t.Fatal(err)
	}
	want := "PUT /projects/csning1998-lab%2Fparent-group-governance/variables/TAG_PUSH_TOKEN"
	if got := (*requests)[0].method + " " + (*requests)[0].path; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// TestHasProject asserts the presence answer for status 200, the absence answer for status 404, and the error for other statuses.
func TestHasProject(t *testing.T) {
	cases := map[string]struct {
		status  int
		want    bool
		wantErr bool
	}{
		"an existing project":  {status: http.StatusOK, want: true},
		"an absent project":    {status: http.StatusNotFound, want: false},
		"a rejected token":     {status: http.StatusUnauthorized, wantErr: true},
		"a server-side defect": {status: http.StatusInternalServerError, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.EscapedPath() != "/projects/personal%2Fsecond-brain" {
					t.Fatalf("got %s %s", r.Method, r.URL.EscapedPath())
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(srv.Close)

			got, err := New(srv.URL, "pat").HasProject(context.Background(), "personal/second-brain")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("HasProject() = %t, %v, want %t and an error %t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestCreateGroupRunner asserts the group runner form and the rejection of a response without a token.
func TestCreateGroupRunner(t *testing.T) {
	runner := GroupRunner{GroupID: "137791469", Description: "shared-runner", TagList: []string{"podman", "local"}, Locked: true, RunUntagged: true}
	cases := map[string]struct {
		response string
		want     CreatedRunner
		wantErr  bool
	}{
		"a created runner returns the token": {response: `{"id":9171,"token":"glrt-issued","token_expires_at":null}`, want: CreatedRunner{ID: 9171, Token: "glrt-issued"}},
		"a response without a token":         {response: `{"id":9171}`, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newGroupRunnerServer(t, tc.response)
			got, err := New(srv.URL, "pat").CreateGroupRunner(context.Background(), runner)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("CreateGroupRunner() = %+v, %v, want %+v and an error %t", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// newGroupRunnerServer answers POST /user/runners with response after checking the group runner form.
func newGroupRunnerServer(t *testing.T, response string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/user/runners" {
			t.Fatalf("got %s %s, want POST /user/runners", r.Method, r.URL.Path)
		}
		checkGroupRunnerForm(t, r.PostForm)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func checkGroupRunnerForm(t *testing.T, form url.Values) {
	t.Helper()
	if form.Get("runner_type") != "group_type" || form.Get("group_id") != "137791469" || form.Get("tag_list") != "podman,local" || form.Get("locked") != "true" || form.Get("run_untagged") != "true" {
		t.Fatalf("got form %v", form)
	}
}
