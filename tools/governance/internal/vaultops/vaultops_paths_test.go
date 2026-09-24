package vaultops

import (
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathsHelpers(t *testing.T) {
	p := Paths{
		ProjectRoot: "/root",
		AnsibleDir:  "/ansible",
		Home:        "/home/u",
	}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"resolveKeysDir", p.resolveKeysDir(), "/root/vault/keys"},
		{"resolveTLSDir", p.resolveTLSDir(), "/root/vault/tls"},
		{"resolveInitFile", p.resolveInitFile(), "/root/vault/keys/init-output.json"},
		{"resolveUnsealKeyFile", p.resolveUnsealKeyFile(), "/root/vault/keys/unseal.key"},
		{"resolveRootTokenFile", p.resolveRootTokenFile(), "/home/u/.vault-token"},
		{"resolveCACertFile", p.resolveCACertFile(), "/root/vault/tls/ca.pem"},
	}
	for _, c := range cases {
		want := filepath.FromSlash(c.want)
		if c.got != want {
			t.Errorf("%s = %q, want %q", c.name, c.got, want)
		}
	}
}

func TestResolveBastionAddrDefaultsToLoopback(t *testing.T) {
	got := (Paths{}).resolveBastionAddr()
	want := "https://127.0.0.1:8200"
	if got != want {
		t.Errorf("resolveBastionAddr() = %q, want %q", got, want)
	}
}

func TestGenerateCertificateSerialProducesDistinctInRangeValues(t *testing.T) {
	a, err := generateCertificateSerial()
	if err != nil {
		t.Fatalf("generateCertificateSerial: %v", err)
	}
	b, err := generateCertificateSerial()
	if err != nil {
		t.Fatalf("generateCertificateSerial: %v", err)
	}
	if a == nil || b == nil {
		t.Fatal("generateCertificateSerial returned a nil *big.Int")
	}
	if a.Cmp(b) == 0 {
		t.Error("two generateCertificateSerial calls returned the same value; expected fresh randomness")
	}
	if a.Sign() < 0 || b.Sign() < 0 {
		t.Error("generateCertificateSerial returned a negative value")
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	if a.Cmp(limit) >= 0 || b.Cmp(limit) >= 0 {
		t.Error("generateCertificateSerial returned a value >= 2^128")
	}
}

func TestWritePEMErrorsWhenDirectoryMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "out.pem")

	err := writePEMFile(path, "TEST BLOCK", []byte("der-bytes"), 0o644)
	if err == nil {
		t.Fatal("writePEMFile: want error, got nil")
	}
	if !strings.Contains(err.Error(), "open") || !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want it to contain %q and %q", err.Error(), "open", path)
	}
}

func TestWritePEMWritesDecodableFileWithGivenMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pem")
	der := []byte("dummy-der-content")

	if err := writePEMFile(path, "TEST BLOCK", der, 0o640); err != nil {
		t.Fatalf("writePEMFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	if block.Type != "TEST BLOCK" {
		t.Errorf("block.Type = %q, want %q", block.Type, "TEST BLOCK")
	}
	if string(block.Bytes) != string(der) {
		t.Errorf("block.Bytes = %q, want %q", block.Bytes, der)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}
}
