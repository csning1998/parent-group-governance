package secretrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

const casConflictSubstring = "check-and-set parameter did not match the current version"

// documentSnapshot represents a consistent view of a KV v2 document.
type documentSnapshot struct {
	fields  map[string]any
	version int
}

func (d documentSnapshot) readStringField(name string) (string, bool) {
	value, ok := d.fields[name].(string)
	return value, ok
}

type fieldStore struct {
	client *vaultapi.Client
	mount  string
	path   string
	field  string
}

func newFieldStore(client *vaultapi.Client, mount, path, field string) fieldStore {
	return fieldStore{client: client, mount: mount, path: path, field: field}
}

func (s fieldStore) dataPath() string           { return s.mount + "/data/" + s.path }
func (s fieldStore) metadataPath() string       { return s.mount + "/metadata/" + s.path }
func (s fieldStore) lockField() string          { return s.field + "_lock" }
func (s fieldStore) rotationStateField() string { return s.field + "_rotation" }

func (s fieldStore) readRotationState(ctx context.Context) (rotationState, bool) {
	doc, ok := s.readDocument(ctx)
	if !ok {
		return rotationState{}, false
	}
	raw, ok := doc.readStringField(s.rotationStateField())
	if !ok {
		return rotationState{}, false
	}
	var st rotationState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return rotationState{}, false
	}
	return st, true
}

// writeRotationState stores the state as a JSON string because Terraform reads every field as a string.
func (s fieldStore) writeRotationState(ctx context.Context, st rotationState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("secretrotate: encode rotation state: %w", err)
	}
	body := map[string]any{"data": map[string]any{
		s.rotationStateField(): string(raw),
	}}
	if err := s.patchOrInitDocument(ctx, body); err != nil {
		return fmt.Errorf("secretrotate: stage rotation state at %s: %w", s.dataPath(), err)
	}
	return nil
}

func (s fieldStore) clearRotationState(ctx context.Context) error {
	writePath := s.dataPath()
	body := map[string]any{"data": map[string]any{s.rotationStateField(): nil}}
	if _, err := s.client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		return fmt.Errorf("secretrotate: clear rotation state at %s: %w", writePath, err)
	}
	return nil
}

func (s fieldStore) readField(ctx context.Context) (string, bool) {
	doc, exists := s.readDocument(ctx)
	if !exists {
		return "", false
	}
	return doc.readStringField(s.field)
}

func (s fieldStore) writeField(ctx context.Context, value string) error {
	return s.patchOrInitDocument(ctx, map[string]any{"data": map[string]any{s.field: value}})
}

func (s fieldStore) writeFieldCAS(ctx context.Context, targetField, value string, version int) error {
	writePath := s.dataPath()
	body := map[string]any{
		"data":    map[string]any{targetField: value},
		"options": map[string]any{"cas": version},
	}
	if version > 0 {
		_, err := s.client.Logical().JSONMergePatch(ctx, writePath, body)
		return err
	}
	_, err := s.client.Logical().WriteWithContext(ctx, writePath, body)
	return err
}

func (s fieldStore) readDocument(ctx context.Context) (documentSnapshot, bool) {
	secret, err := s.client.Logical().ReadWithContext(ctx, s.dataPath())
	if err != nil || secret == nil {
		return documentSnapshot{}, false
	}
	fields, _ := secret.Data["data"].(map[string]any)
	version := 0
	if meta, ok := secret.Data["metadata"].(map[string]any); ok {
		version = parseVersionNumber(meta["version"])
	}
	return documentSnapshot{fields: fields, version: version}, true
}

// patchOrInitDocument falls back to full write on 404 when no document exists yet.
func (s fieldStore) patchOrInitDocument(ctx context.Context, body map[string]any) error {
	writePath := s.dataPath()
	if _, err := s.client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		if !isMissingDocument(err) {
			return fmt.Errorf("secretrotate: patch %s: %w", writePath, err)
		}
		if _, err := s.client.Logical().WriteWithContext(ctx, writePath, body); err != nil {
			return fmt.Errorf("secretrotate: write %s: %w", writePath, err)
		}
	}
	return nil
}

// hasVersionHistory reports whether the metadata path records any prior version.
func (s fieldStore) hasVersionHistory(ctx context.Context) bool {
	secret, err := s.client.Logical().ReadWithContext(ctx, s.metadataPath())
	if err != nil || secret == nil {
		return false
	}
	return parseVersionNumber(secret.Data["current_version"]) > 0
}

// isDestroyedOutOfBand confirms that the data path reads back absent even though metadata records prior versions.
func (s fieldStore) isDestroyedOutOfBand(ctx context.Context) bool {
	if !s.hasVersionHistory(ctx) {
		return false
	}
	_, exists := s.readDocument(ctx)
	return !exists
}

func isCASConflict(err error) bool {
	if err == nil {
		return false
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		if respErr.StatusCode != http.StatusBadRequest {
			return false
		}
		for _, msg := range respErr.Errors {
			if strings.Contains(msg, casConflictSubstring) {
				return true
			}
		}
		return false
	}
	return strings.Contains(err.Error(), casConflictSubstring)
}

func isMissingDocument(err error) bool {
	var respErr *vaultapi.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}

func parseVersionNumber(raw any) int {
	switch v := raw.(type) {
	case float64:
		return int(v)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0
		}
		return int(n)
	default:
		return 0
	}
}

func readField(ctx context.Context, client *vaultapi.Client, mount, path, field string) (string, bool) {
	return newFieldStore(client, mount, path, field).readField(ctx)
}

func writeField(ctx context.Context, client *vaultapi.Client, mount, path, field, value string) error {
	return newFieldStore(client, mount, path, field).writeField(ctx, value)
}

func readRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string) (rotationState, bool) {
	return newFieldStore(client, mount, path, field).readRotationState(ctx)
}

func writeRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string, st rotationState) error {
	return newFieldStore(client, mount, path, field).writeRotationState(ctx, st)
}
