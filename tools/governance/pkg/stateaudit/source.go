package stateaudit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// ErrVersionMissing reports a state version which the backend no longer holds.
var ErrVersionMissing = errors.New("stateaudit: the backend holds no such state version")

// Layer is one Terraform layer and the address of its HTTP backend.
type Layer struct {
	Name    string
	Address string
}

// StateSource fetches states from a backend address.
type StateSource interface {
	FetchCurrent(ctx context.Context, address string) ([]byte, error)
	FetchVersion(ctx context.Context, address string, serial int) ([]byte, error)
}

// DiscoverLayers returns every layer below layersDir with backend "http".
func DiscoverLayers(layersDir string) ([]Layer, error) {
	dirs, err := filepath.Glob(filepath.Join(layersDir, "*"))
	if err != nil {
		return nil, fmt.Errorf("stateaudit: list %s: %w", layersDir, err)
	}
	parser := hclparse.NewParser()
	var layers []Layer
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		address, err := readBackendAddress(parser, dir)
		if err != nil {
			return nil, fmt.Errorf("stateaudit: layer %s: %w", filepath.Base(dir), err)
		}
		if address != "" {
			layers = append(layers, Layer{Name: filepath.Base(dir), Address: address})
		}
	}
	return layers, nil
}

// readBackendAddress returns the literal address of backend "http" in dir, or "" when dir declares none.
func readBackendAddress(parser *hclparse.Parser, dir string) (string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		return "", err
	}
	for _, file := range files {
		parsed, diags := parser.ParseHCLFile(file)
		if diags.HasErrors() {
			return "", fmt.Errorf("parse %s: %w", file, diags)
		}
		body, ok := parsed.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			backend := findHTTPBackend(block)
			if backend != nil {
				return readLiteralAddress(backend)
			}
		}
	}
	return "", nil
}

func findHTTPBackend(block *hclsyntax.Block) *hclsyntax.Block {
	if block.Type != "terraform" {
		return nil
	}
	for _, nested := range block.Body.Blocks {
		if nested.Type == "backend" && len(nested.Labels) == 1 && nested.Labels[0] == "http" {
			return nested
		}
	}
	return nil
}

func readLiteralAddress(backend *hclsyntax.Block) (string, error) {
	attr, ok := backend.Body.Attributes["address"]
	if !ok {
		return "", errors.New("backend \"http\" declares no address")
	}
	value, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || value.Type() != cty.String || value.AsString() == "" {
		return "", errors.New("backend \"http\" address is not a string literal")
	}
	return value.AsString(), nil
}

// HTTPSource reads states from an HTTP backend with basic authentication.
type HTTPSource struct {
	Client   *http.Client
	Username string
	Password string
}

// FetchCurrent returns the current state at address.
func (s HTTPSource) FetchCurrent(ctx context.Context, address string) ([]byte, error) {
	body, status, err := s.get(ctx, address)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("stateaudit: GET %s returned %d", address, status)
	}
	return body, nil
}

// FetchVersion returns the state version serial at address.
func (s HTTPSource) FetchVersion(ctx context.Context, address string, serial int) ([]byte, error) {
	url := address + "/versions/" + strconv.Itoa(serial)
	body, status, err := s.get(ctx, url)
	switch {
	case err != nil:
		return nil, err
	case status == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrVersionMissing, url)
	case status != http.StatusOK:
		return nil, fmt.Errorf("stateaudit: GET %s returned %d", url, status)
	}
	return body, nil
}

func (s HTTPSource) get(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("stateaudit: build request for %s: %w", url, err)
	}
	req.SetBasicAuth(s.Username, s.Password)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("stateaudit: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("stateaudit: read %s: %w", url, err)
	}
	return body, resp.StatusCode, nil
}
