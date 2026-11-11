// Package gitlabapi provides an HTTP client for GitLab CI/CD variable endpoints.
package gitlabapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound marks a GitLab response with status 404.
var ErrNotFound = errors.New("gitlabapi: resource not found")

// Client authenticates every request with one personal access token.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Variable represents a GitLab CI/CD variable alongside storage and visibility attributes.
type Variable struct {
	Key       string
	Value     string
	Masked    bool
	Hidden    bool
	Raw       bool
	Protected bool
}

// New returns a Client for the REST API at baseURL, for example https://gitlab.com/api/v4.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// UpsertGroupVariable creates or updates a CI/CD variable within the specified group.
func (c *Client) UpsertGroupVariable(ctx context.Context, groupID string, v Variable) error {
	return c.upsertVariable(ctx, "groups/"+url.PathEscape(groupID)+"/variables", v)
}

// UpsertProjectVariable creates or updates a project-level CI/CD variable at the specified project path.
func (c *Client) UpsertProjectVariable(ctx context.Context, projectPath string, v Variable) error {
	return c.upsertVariable(ctx, "projects/"+url.PathEscape(projectPath)+"/variables", v)
}

// HasProject verifies token access to the specified project, returning false when GitLab responds with 404 Not Found.
func (c *Client) HasProject(ctx context.Context, projectPath string) (bool, error) {
	err := c.send(ctx, http.MethodGet, "projects/"+url.PathEscape(projectPath), nil, nil)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// GroupRunner defines registration parameters of a GitLab group runner.
type GroupRunner struct {
	GroupID     string
	Description string
	TagList     []string
	Locked      bool
	RunUntagged bool
}

// CreatedRunner represents registration credentials of a newly provisioned runner.
type CreatedRunner struct {
	ID    int    `json:"id"`
	Token string `json:"token"`
}

// CreateGroupRunner provisions a group-level runner linked to the token owner and returns its identifier and authentication token.
func (c *Client) CreateGroupRunner(ctx context.Context, r GroupRunner) (CreatedRunner, error) {
	form := url.Values{}
	form.Set("runner_type", "group_type")
	form.Set("group_id", r.GroupID)
	form.Set("description", r.Description)
	form.Set("tag_list", strings.Join(r.TagList, ","))
	form.Set("locked", strconv.FormatBool(r.Locked))
	form.Set("run_untagged", strconv.FormatBool(r.RunUntagged))
	var created CreatedRunner
	if err := c.send(ctx, http.MethodPost, "user/runners", form, &created); err != nil {
		return CreatedRunner{}, err
	}
	if created.Token == "" {
		return CreatedRunner{}, fmt.Errorf("gitlabapi: runner %d returned no token", created.ID)
	}
	return created, nil
}

// upsertVariable supplies the hidden attribute only during resource creation, matching immutable GitLab API constraints.
func (c *Client) upsertVariable(ctx context.Context, collection string, v Variable) error {
	form := url.Values{}
	form.Set("value", v.Value)
	form.Set("raw", strconv.FormatBool(v.Raw))
	form.Set("protected", strconv.FormatBool(v.Protected))
	form.Set("masked", strconv.FormatBool(v.Masked))
	err := c.send(ctx, http.MethodPut, collection+"/"+url.PathEscape(v.Key), form, nil)
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	form.Set("key", v.Key)
	if v.Hidden {
		form.Del("masked")
		form.Set("masked_and_hidden", "true")
	}
	return c.send(ctx, http.MethodPost, collection, form, nil)
}

// send omits form payloads and raw response decode errors from diagnostics to prevent credential disclosure.
func (c *Client) send(ctx context.Context, method, path string, form url.Values, out any) error {
	endpoint := c.baseURL + "/" + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("gitlabapi: build %s %s: %w", method, endpoint, err)
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gitlabapi: %s %s: %w", method, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s %s", ErrNotFound, method, endpoint)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gitlabapi: %s %s returned %d: %s", method, endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("gitlabapi: decode the response of %s %s", method, endpoint)
	}
	return nil
}
