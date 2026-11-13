// Package sonarusertokens provides an HTTP client for the SonarQube api/user_tokens web service.
package sonarusertokens

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client authenticates API requests using HTTP basic authentication with SonarQube user credentials.
type Client struct {
	endpoint string
	login    string
	password string
	http     *http.Client
}

// Token represents SonarQube token metadata excluding secret token values.
type Token struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// New initializes a SonarQube token client for the specified endpoint.
func New(endpoint, login, password string) *Client {
	return &Client{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		login:    login,
		password: password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Generate creates a token with the specified name and tokenType. Generate returns the secret token value.
func (c *Client) Generate(ctx context.Context, name, tokenType string) (string, error) {
	form := url.Values{}
	form.Set("name", name)
	form.Set("type", tokenType)
	var generated struct {
		Token string `json:"token"`
	}
	if err := c.send(ctx, http.MethodPost, "generate", form, &generated); err != nil {
		return "", err
	}
	if generated.Token == "" {
		return "", fmt.Errorf("sonarusertokens: generate %s returned no token", name)
	}
	return generated.Token, nil
}

// List retrieves token metadata entries for the authenticated user.
func (c *Client) List(ctx context.Context) ([]Token, error) {
	var listed struct {
		UserTokens []Token `json:"userTokens"`
	}
	if err := c.send(ctx, http.MethodGet, "search", nil, &listed); err != nil {
		return nil, err
	}
	return listed.UserTokens, nil
}

// Revoke invalidates the specified token for the authenticated user.
func (c *Client) Revoke(ctx context.Context, name string) error {
	form := url.Values{}
	form.Set("name", name)
	return c.send(ctx, http.MethodPost, "revoke", form, nil)
}

// send suppresses decode errors to prevent echoing raw response fragments containing sensitive token data.
func (c *Client) send(ctx context.Context, method, action string, form url.Values, out any) error {
	endpoint := c.endpoint + "/" + action
	req, err := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("sonarusertokens: build %s %s: %w", method, endpoint, err)
	}
	req.SetBasicAuth(c.login, c.password)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("sonarusertokens: %s %s: %w", method, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sonarusertokens: %s %s returned %d: %s", method, endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("sonarusertokens: decode the response of %s %s", method, endpoint)
	}
	return nil
}
