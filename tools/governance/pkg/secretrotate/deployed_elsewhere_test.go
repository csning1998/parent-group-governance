package secretrotate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

// deployedElsewhereCase drives one Rotate call whose Deploy observes an outside writer replace the
// field, then reports how resolveDeployedElsewhere treats that replacement.
type deployedElsewhereCase struct {
	name      string
	verifyErr bool
	failClear bool
	wantLog   string
	wantErr   string
}

func TestResolveDeployedElsewhere(t *testing.T) {
	cases := []deployedElsewhereCase{
		{
			name:      "reports an inconclusive verification of the raced value",
			verifyErr: true,
			wantErr:   "verifying the raced value failed",
		},
		{
			name:      "keeps the staged record when clearing it fails",
			failClear: true,
			wantErr:   "clearing the stale rotation state failed",
		},
		{
			name:    "logs the value a concurrent write already stored",
			wantLog: "accepting that value",
		},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func logContains(messages []string, sub string) bool {
	for _, message := range messages {
		if strings.Contains(message, sub) {
			return true
		}
	}
	return false
}

func (c deployedElsewhereCase) assertExpectedError(t *testing.T, got string, err error) {
	var racedErr *deployRaceResolvedError
	if err == nil || !errors.As(err, &racedErr) {
		t.Fatalf("Rotate = %q, %v, want a deployRaceResolvedError", got, err)
	}
	if racedErr.Error() == "" || racedErr.Unwrap() == nil {
		t.Fatalf("raced error = %v, unwrap = %v, want the text and the deploy cause", racedErr, racedErr.Unwrap())
	}
	if got != "" || !strings.Contains(err.Error(), c.wantErr) {
		t.Fatalf("Rotate = %q, %v, want error containing %q", got, err, c.wantErr)
	}
}

func (c deployedElsewhereCase) assertSuccess(t *testing.T, got, raced string, err error, logs []string) {
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got != raced {
		t.Errorf("Rotate = %q, want %q", got, raced)
	}
	if c.wantLog != "" && !logContains(logs, c.wantLog) {
		t.Errorf("logs = %q, want a message containing %q", logs, c.wantLog)
	}
}

func (c deployedElsewhereCase) newTestSpec(t *testing.T, client *vaultapi.Client, store *fakeKVv2, raced string) Spec {
	outsiderWrote := false
	spec := lockTestSpec()
	spec.Verify = func(ctx context.Context, secret string) (bool, error) {
		if c.verifyErr && secret == raced {
			return false, errors.New("verify down")
		}
		return secret == raced || (secret == "old-value" && !outsiderWrote), nil
	}
	spec.Deploy = func(ctx context.Context, previous, next string) error {
		outsiderWrote = true
		if err := writeField(context.Background(), client, "secret", "app/infra", "password", raced); err != nil {
			t.Fatalf("simulate an out-of-band write: %v", err)
		}
		if c.failClear {
			// The API client retries a rejected patch, so one refusal is not enough.
			store.failNextPatches(5)
		}
		return fmt.Errorf("%w: test", ErrAuthRejected)
	}
	return spec
}

func (c deployedElsewhereCase) run(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	const raced = "raced-in-value"
	spec := c.newTestSpec(t, client, store, raced)

	var logs []string
	got, err := Rotate(context.Background(), client, spec, func(message string) {
		logs = append(logs, message)
	})
	if c.wantErr != "" {
		c.assertExpectedError(t, got, err)
		return
	}
	c.assertSuccess(t, got, raced, err, logs)
}
