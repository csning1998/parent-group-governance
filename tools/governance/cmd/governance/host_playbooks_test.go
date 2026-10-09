package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

// hostFixture is an app whose ansible-playbook is a recorder on PATH, which fails on a playbook named in failOn.
type hostFixture struct {
	a   *app
	log string
}

func TestApplyAllMenuOption_RunsEveryHostStep(t *testing.T) {
	f := newHostFixture(t, "example-become", "")

	err := f.a.buildMenuOptions()[0].run(context.Background())
	if err != nil {
		t.Fatalf("Apply All: %v", err)
	}
	if got := len(f.playbooks(t)); got != 3 {
		t.Errorf("playbook runs = %d, want 3", got)
	}
}

func TestHostMenuOptions_RunTheirPlaybookAlone(t *testing.T) {
	cases := map[string]string{
		"[Host] Apply Workstation SELinux Policy and File Contexts":                "playbooks/workstation_selinux.yaml",
		"[Host] Apply Workstation Libvirt Network and Bastion Vault Prerequisites": "playbooks/workstation_libvirt.yaml",
		"[Host] Apply Workstation Vault Proxies":                                   "playbooks/workstation_vault_proxy.yaml",
	}
	for label, playbook := range cases {
		t.Run(label, func(t *testing.T) {
			f := newHostFixture(t, "example-become", "")
			options := f.a.buildMenuOptions()
			i := slices.IndexFunc(options, func(o menuOption) bool { return o.label == label })
			if i < 0 {
				t.Fatalf("menu lacks %q", label)
			}

			err := options[i].run(context.Background())
			if err != nil {
				t.Fatalf("%s: %v", label, err)
			}
			if got := f.playbooks(t); !slices.Equal(got, []string{playbook}) {
				t.Errorf("playbooks = %q, want %q alone", got, playbook)
			}
		})
	}
}

func TestRunHostAll_KeepsAnExistingLocalCA(t *testing.T) {
	f := newHostFixture(t, "example-become", "")
	caFile := filepath.Join(f.a.root, "vault", "tls", "ca.pem")
	err := os.MkdirAll(filepath.Dir(caFile), 0o755)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err = os.WriteFile(caFile, []byte("example existing CA"), 0o644)
	if err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}

	err = f.a.runHostAll(context.Background())
	if err != nil {
		t.Fatalf("runHostAll: %v", err)
	}
	if data, _ := os.ReadFile(caFile); string(data) != "example existing CA" {
		t.Errorf("ca.pem = %q, want the existing CA untouched", data)
	}
}

func TestRunHostAll_RunsEveryStepInBootstrapOrder(t *testing.T) {
	f := newHostFixture(t, "example-become", "")

	err := f.a.runHostAll(context.Background())
	if err != nil {
		t.Fatalf("runHostAll: %v", err)
	}

	want := []string{"playbooks/workstation_selinux.yaml", "playbooks/workstation_libvirt.yaml", "playbooks/workstation_vault_proxy.yaml"}
	if got := f.playbooks(t); !slices.Equal(got, want) {
		t.Errorf("playbooks = %q, want %q", got, want)
	}
	for _, call := range f.calls(t) {
		if !strings.HasSuffix(call, "become=set") {
			t.Errorf("call %q, want the become password in the environment", call)
		}
	}
	caDir := filepath.Join(f.a.root, "vault", "tls")
	if _, err := os.Stat(filepath.Join(caDir, "ca.pem")); err != nil {
		t.Errorf("stat ca.pem: %v, want the local CA before the Vault Proxies", err)
	}
	if calls := f.calls(t); !strings.Contains(calls[len(calls)-1], caDir) {
		t.Errorf("Vault Proxy call %q, want the CA directory %s", calls[len(calls)-1], caDir)
	}
}

func TestRunHostPlaybooks_BlankPasswordRunsNoPlaybook(t *testing.T) {
	f := newHostFixture(t, "", "")

	err := f.a.runHostAll(context.Background())
	if err != nil {
		t.Fatalf("runHostAll: %v", err)
	}
	if calls := f.calls(t); len(calls) != 0 {
		t.Errorf("calls = %q, want none after a blank password", calls)
	}
	if _, err := os.Stat(filepath.Join(f.a.root, "vault", "tls")); !os.IsNotExist(err) {
		t.Errorf("stat vault/tls: %v, want no local CA after a blank password", err)
	}
}

func TestRunHostPlaybooks_StopsAtTheFirstFailure(t *testing.T) {
	f := newHostFixture(t, "example-become", "workstation_libvirt")

	err := f.a.runHostAll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "workstation_libvirt.yaml") {
		t.Fatalf("runHostAll error = %v, want the failing libvirt playbook", err)
	}
	if err != nil && strings.Contains(err.Error(), "example-become") {
		t.Errorf("runHostAll error = %v, want no become password", err)
	}
	want := []string{"playbooks/workstation_selinux.yaml", "playbooks/workstation_libvirt.yaml"}
	if got := f.playbooks(t); !slices.Equal(got, want) {
		t.Errorf("playbooks = %q, want %q", got, want)
	}
}

func newHostFixture(t *testing.T, becomeAnswer, failOn string) *hostFixture {
	t.Helper()
	root, bin := t.TempDir(), t.TempDir()
	log := filepath.Join(t.TempDir(), "calls.log")
	script := "#!/bin/sh\n" +
		"printf '%s become=%s\\n' \"$*\" \"${ANSIBLE_BECOME_PASS:+set}\" >> '" + log + "'\n" +
		"if [ -n '" + failOn + "' ]; then case \"$*\" in *'" + failOn + "'*) exit 1 ;; esac; fi\n"
	err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(script), 0o700)
	if err != nil {
		t.Fatalf("write fake ansible-playbook: %v", err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	err = os.MkdirAll(filepath.Join(root, "ansible"), 0o755)
	if err != nil {
		t.Fatalf("mkdir ansible: %v", err)
	}

	return &hostFixture{
		a: &app{
			root:       root,
			home:       t.TempDir(),
			ansibleDir: filepath.Join(root, "ansible"),
			topology:   topology.Topology{BastionVault: topology.BastionVault{LoopbackAddress: "127.0.0.1", PublishAddress: "192.0.2.10", APIPort: 8200}},
			out:        ui.New(io.Discard, io.Discard),
			in:         bufio.NewReader(strings.NewReader(becomeAnswer + "\n")),
		},
		log: log,
	}
}

// calls returns one line per ansible-playbook run, holding the arguments and whether the become password arrived.
func (f *hostFixture) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read calls: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (f *hostFixture) playbooks(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, call := range f.calls(t) {
		for _, field := range strings.Fields(call) {
			if strings.HasPrefix(field, "playbooks/") {
				names = append(names, field)
			}
		}
	}
	return names
}
