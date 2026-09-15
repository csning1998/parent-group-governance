package ansibleops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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

func TestRunPlaybookMissingPlaybookFileFails(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()

	err := RunPlaybook(context.Background(), dir, "", filepath.Join(dir, "no-such-playbook.yaml"), &playbook.AnsiblePlaybookOptions{}, nil)
	if err == nil {
		t.Error("RunPlaybook on a missing playbook file = nil error, want error")
	}
}

func TestRunPlaybookSucceedsWithAbsolutePlaybookAndNoRunDir(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	playbookPath := filepath.Join(dir, "noop.yaml")
	if err := os.WriteFile(playbookPath, []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if err := RunPlaybook(context.Background(), dir, "", playbookPath, &playbook.AnsiblePlaybookOptions{}, nil); err != nil {
		t.Errorf("RunPlaybook on a no-op playbook = %v, want nil", err)
	}
}

func TestRunPlaybookResolvesRelativePlaybookAgainstRunDir(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noop.yaml"), []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if err := RunPlaybook(context.Background(), dir, dir, "noop.yaml", &playbook.AnsiblePlaybookOptions{}, nil); err != nil {
		t.Errorf("RunPlaybook with runDir set and a relative playbook path = %v, want nil", err)
	}
}

func TestRunPlaybookRelativePlaybookWithoutRunDirFails(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noop.yaml"), []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	err := RunPlaybook(context.Background(), dir, "", "noop.yaml", &playbook.AnsiblePlaybookOptions{}, nil)
	if err == nil {
		t.Error("RunPlaybook with a relative playbook and no runDir = nil error, want error")
	}
}

func TestRunPlaybookToleratesMissingAnsibleConfigFile(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	playbookPath := filepath.Join(dir, "noop.yaml")
	if err := os.WriteFile(playbookPath, []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	nonexistentAnsibleDir := filepath.Join(dir, "no-such-ansible-dir")
	if err := RunPlaybook(context.Background(), nonexistentAnsibleDir, "", playbookPath, &playbook.AnsiblePlaybookOptions{}, nil); err != nil {
		t.Errorf("RunPlaybook with a missing ansible.cfg = %v, want nil", err)
	}
}

func TestRunPlaybookPassesThroughPlaybookOptions(t *testing.T) {
	requireAnsiblePlaybook(t)
	dir := t.TempDir()
	playbookPath := filepath.Join(dir, "noop.yaml")
	if err := os.WriteFile(playbookPath, []byte(noopPlaybookYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	opts := &playbook.AnsiblePlaybookOptions{Tags: "never-matches"}
	if err := RunPlaybook(context.Background(), dir, "", playbookPath, opts, nil); err != nil {
		t.Errorf("RunPlaybook with Tags set = %v, want nil", err)
	}
}
