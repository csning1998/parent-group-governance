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

// send excludes form payload data from error diagnostics to prevent credential disclosure.
func (c *Client) send(ctx context.Context, method, path string, form url.Values, out any) error {
	endpoint := c.baseURL + "/" + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("gitlabapi: build %s %s: %w", method, endpoint, err)
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		return fmt.Errorf("gitlabapi: decode the response of %s %s: %w", method, endpoint, err)
	}
	return nil
}
