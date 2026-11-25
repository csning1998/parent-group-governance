// Package terraform inspects direnv approvals and executes Terraform layers in isolated direnv subprocesses.
package terraform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrDirenvNotAllowed reports a layer directory whose .envrc has not been approved via direnv allow.
var ErrDirenvNotAllowed = errors.New("terraform: direnv not allowed")

type direnvStatusOutput struct {
	State struct {
		FoundRC *struct {
			Allowed int    `json:"allowed"`
			Path    string `json:"path"`
		} `json:"foundRC"`
	} `json:"state"`
}

// CheckDirenvAllowed inspects direnv status --json in dir and reports whether its .envrc is approved.
func CheckDirenvAllowed(ctx context.Context, dir string) (bool, string, error) {
	cmd := exec.CommandContext(ctx, direnvBinary, "status", "--json")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return false, "", fmt.Errorf("terraform: direnv status in %s failed (%s): %w", dir, strings.TrimSpace(stderr.String()), err)
	}

	var status direnvStatusOutput
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		return false, "", fmt.Errorf("terraform: decode direnv status in %s: %w", dir, err)
	}
	if status.State.FoundRC == nil {
		return false, "", nil
	}
	return status.State.FoundRC.Allowed == 0, status.State.FoundRC.Path, nil
}
