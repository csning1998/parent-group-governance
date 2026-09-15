package vaultops

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", path, err)
	}
	return cert
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want)
	}
}

type fakeEnv struct{ kv map[string]string }

func newFakeEnv() *fakeEnv { return &fakeEnv{kv: map[string]string{}} }

func (e *fakeEnv) Set(k, v string) { e.kv[k] = v }

func discardOut() *ui.Printer { return ui.New(io.Discard, io.Discard) }
