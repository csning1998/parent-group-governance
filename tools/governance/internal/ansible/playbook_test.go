package ansible

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apenella/go-ansible/v2/pkg/playbook"
)

const noopPlaybookYAML = "---\n- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks: []\n"

func requireAnsiblePlaybook(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip("ansible-playbook not on PATH")
	}
}

func TestExecutePlaybookMissingPlaybookFileFails(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()

	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   dir,
		PlaybookFile: filepath.Join(dir, "no-such-playbook.yaml"),
		Options:      &playbook.AnsiblePlaybookOptions{},
	})
	if err == nil {
		t.Error("ExecutePlaybook on a missing playbook file = nil error, want error")
	}
}

func TestExecutePlaybookErrorOmitsExtraEnvValues(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	const secret = "become-password-fixture"

	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   dir,
		PlaybookFile: filepath.Join(dir, "no-such-playbook.yaml"),
		Options:      &playbook.AnsiblePlaybookOptions{},
		ExtraEnv:     map[string]string{"ANSIBLE_BECOME_PASS": secret},
	})
	if err == nil {
		t.Fatal("ExecutePlaybook on a missing playbook file = nil error, want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("ExecutePlaybook error = %q, want an error without the extraEnv value", err)
	}
}

func TestExecutePlaybookSucceedsWithAbsolutePlaybookAndNoRunDir(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	playbookPath := filepath.Join(dir, "noop.yaml")
	if err := os.WriteFile(playbookPath, []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   dir,
		PlaybookFile: playbookPath,
		Options:      &playbook.AnsiblePlaybookOptions{},
	})
	if err != nil {
		t.Errorf("ExecutePlaybook on a no-op playbook = %v, want nil", err)
	}
}

func TestExecutePlaybookResolvesRelativePlaybookAgainstRunDir(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noop.yaml"), []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   dir,
		RunDir:       dir,
		PlaybookFile: "noop.yaml",
		Options:      &playbook.AnsiblePlaybookOptions{},
	})
	if err != nil {
		t.Errorf("ExecutePlaybook with runDir set and a relative playbook path = %v, want nil", err)
	}
}

func TestExecutePlaybookRelativePlaybookWithoutRunDirFails(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noop.yaml"), []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   dir,
		PlaybookFile: "noop.yaml",
		Options:      &playbook.AnsiblePlaybookOptions{},
	})
	if err == nil {
		t.Error("ExecutePlaybook with a relative playbook and no runDir = nil error, want error")
	}
}

func TestExecutePlaybookToleratesMissingAnsibleConfigFile(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	playbookPath := filepath.Join(dir, "noop.yaml")
	if err := os.WriteFile(playbookPath, []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	nonexistentAnsibleDir := filepath.Join(dir, "no-such-ansible-dir")
	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   nonexistentAnsibleDir,
		PlaybookFile: playbookPath,
		Options:      &playbook.AnsiblePlaybookOptions{},
	})
	if err != nil {
		t.Errorf("ExecutePlaybook with a missing ansible.cfg = %v, want nil", err)
	}
}

func TestExecutePlaybookPassesThroughPlaybookOptions(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	playbookPath := filepath.Join(dir, "noop.yaml")
	if err := os.WriteFile(playbookPath, []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	opts := &playbook.AnsiblePlaybookOptions{Tags: "never-matches"}
	err := ExecutePlaybook(context.Background(), PlaybookRequest{
		AnsibleDir:   dir,
		PlaybookFile: playbookPath,
		Options:      opts,
	})
	if err != nil {
		t.Errorf("ExecutePlaybook with Tags set = %v, want nil", err)
	}
}
