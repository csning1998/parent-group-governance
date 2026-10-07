// Package httprotate implements one generic secretrotate.DeployFunc for a REST change-password
// endpoint. Refer to docs/secretrotate-design.md for the design.
package httprotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

// ErrUnauthorized marks a rejected rotation attempt.
var ErrUnauthorized = errors.New("httprotate: request rejected as unauthorized")

var noRedirectClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// FormSpec describes one REST change-password endpoint and one credential validation endpoint entirely as data.
type FormSpec struct {
	URL       string
	VerifyURL string
	Login     string
}

// Deploy implements secretrotate.DeployFunc against the endpoint FormSpec describes.
func (s FormSpec) Deploy(ctx context.Context, previous, next string) error {
	form := url.Values{}
	form.Set("login", s.Login)
	form.Set("password", next)
	form.Set("previousPassword", previous)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("httprotate: build request for %s: %w", s.URL, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.Login, previous)

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return fmt.Errorf("httprotate: call %s: %w", s.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: %w: %s", ErrUnauthorized, secretrotate.ErrAuthRejected, strings.TrimSpace(string(body)))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("httprotate: %s returned %d: %s", s.URL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Verify implements secretrotate.VerifyFunc through a GET on VerifyURL authenticated with secret.
// The endpoint MUST answer 200 with a JSON boolean "valid", and every other answer proves nothing.
func (s FormSpec) Verify(ctx context.Context, secret string) (bool, error) {
	if s.VerifyURL == "" {
		return false, errors.New("httprotate: no verify URL configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.VerifyURL, nil)
	if err != nil {
		return false, fmt.Errorf("httprotate: build request for %s: %w", s.VerifyURL, err)
	}
	req.SetBasicAuth(s.Login, secret)

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("httprotate: call %s: %w", s.VerifyURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("httprotate: %s returned %d: %s", s.VerifyURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var answer struct {
		Valid *bool `json:"valid"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.Valid == nil {
		return false, fmt.Errorf("httprotate: %s answered without a boolean valid field", s.VerifyURL)
	}
	return *answer.Valid, nil
}
