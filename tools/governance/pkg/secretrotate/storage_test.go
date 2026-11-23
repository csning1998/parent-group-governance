package secretrotate

import (
	"context"
	"net/http"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

// roundTripCase is one row of TestWriteFieldRoundTripsSpecialCharacters. seed decides which of
// the two writeField branches the case exercises: a seeded path patches, an empty path creates.
type roundTripCase struct {
	name string
	seed bool
	evil string
}

func TestExistsReflectsWhetherVaultStoresTheField(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	spec := Spec{Mount: "secret", Path: "app/infra", Field: "password"}

	if Exists(context.Background(), client, spec) {
		t.Error("Exists = true before any value is written, want false")
	}

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "v1"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	if !Exists(context.Background(), client, spec) {
		t.Error("Exists = false after a value is written, want true")
	}
}

// TestIsCASConflictRequiresTheCASStatusCode covers a false-positive risk in matching against the
// formatted error string alone: the exact check-and-set wording under an unrelated HTTP status
// MUST NOT be classified as a version conflict.
func TestIsCASConflictRequiresTheCASStatusCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "400 with the real conflict message is a conflict",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusBadRequest, Errors: []string{casConflictSubstring}},
			want: true,
		},
		{
			name: "500 echoing the identical wording is not a conflict",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusInternalServerError, Errors: []string{casConflictSubstring}},
			want: false,
		},
		{
			name: "400 with an unrelated message is not a conflict",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusBadRequest, Errors: []string{"permission denied"}},
			want: false,
		},
		{
			name: "a nil error is not a conflict",
			err:  nil,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isCASConflict(c.err); got != c.want {
				t.Errorf("isCASConflict(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestWriteFieldCreatesOnFirstWriteAfterAPatchRejection covers the boundary on which the
// probe-free design of writeField depends: a patch against a path with no document yet MUST
// fall back to a create, at the cost of one rejected patch attempt plus the create itself.
func TestWriteFieldCreatesOnFirstWriteAfterAPatchRejection(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	ctx := context.Background()

	before := len(store.requests)
	if err := writeField(ctx, client, "secret", "app/infra", "password", "first-value"); err != nil {
		t.Fatalf("writeField: %v", err)
	}
	issued := store.requests[before:]
	if len(issued) != 2 {
		t.Errorf("requests issued = %v, want the rejected patch followed by exactly one create", issued)
	}

	got, ok := readField(ctx, client, "secret", "app/infra", "password")
	if !ok || got != "first-value" {
		t.Errorf("readField = %q, ok=%v, want %q committed", got, ok, "first-value")
	}
}

// TestWriteFieldPatchesWithoutAnExistenceProbe covers the round trip cost of writeField: updating
// an already-seeded field MUST issue exactly one request, the patch itself, never a leading probe
// read to decide which write form applies.
func TestWriteFieldPatchesWithoutAnExistenceProbe(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	ctx := context.Background()
	seedField(t, client, "password", "old-value")

	before := len(store.requests)
	if err := writeField(ctx, client, "secret", "app/infra", "password", "new-value"); err != nil {
		t.Fatalf("writeField: %v", err)
	}
	issued := store.requests[before:]
	if len(issued) != 1 {
		t.Errorf("requests issued = %v, want exactly one patch and no leading existence probe", issued)
	}

	got, ok := readField(ctx, client, "secret", "app/infra", "password")
	if !ok || got != "new-value" {
		t.Errorf("readField = %q, ok=%v, want %q committed", got, ok, "new-value")
	}
}

// TestWriteFieldRoundTripsSpecialCharacters covers both write paths selected by writeField.
// WriteWithContext writes a path without a document. JSONMergePatch writes a path with an existing document.
// Both paths MUST store the value as one opaque string and never as extra JSON structure.
func TestWriteFieldRoundTripsSpecialCharacters(t *testing.T) {
	cases := []roundTripCase{
		{"create path, no existing document", false, "\"}}; DROP TABLE secrets; --\n\x00<script>\\"},
		{"patch path, existing document", true, `value","injected":"true`},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestWriteRotationStateKeepsEveryFieldAString covers the Terraform consumer of the same path,
// which fails with a value conversion error on any field which is not a string.
func TestWriteRotationStateKeepsEveryFieldAString(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	staged := rotationState{Previous: "old-value", PendingNext: "next-value"}
	if err := writeRotationState(context.Background(), client, "secret", "app/infra", "password", staged); err != nil {
		t.Fatalf("writeRotationState: %v", err)
	}

	secret, err := client.Logical().ReadWithContext(context.Background(), "secret/data/app/infra")
	if err != nil || secret == nil {
		t.Fatalf("read document: %v", err)
	}
	data, _ := secret.Data["data"].(map[string]any)
	for key, value := range data {
		if _, ok := value.(string); !ok {
			t.Errorf("field %s contains %T, want string", key, value)
		}
	}

	got, ok := readRotationState(context.Background(), client, "secret", "app/infra", "password")
	if !ok || got != staged {
		t.Errorf("readRotationState = %+v, ok=%v, want %+v", got, ok, staged)
	}
}

func (c roundTripCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if c.seed {
		seedField(t, client, "seed", "x")
	}
	seedField(t, client, "password", c.evil)

	got, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || got != c.evil {
		t.Errorf("readField = %q, ok=%v, want %q preserved as one opaque value", got, ok, c.evil)
	}
	injected, ok := readField(context.Background(), client, "secret", "app/infra", "injected")
	if ok {
		t.Errorf("sibling field injected=%q appeared, want the crafted value treated as one string", injected)
	}
}
