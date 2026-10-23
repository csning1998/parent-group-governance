package vaultops

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unsupportedSigner carries a public key type which x509 neither signs with nor marshals.
type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey { return struct{}{} }

func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unsupported signer")
}

func failKeyGeneration() (crypto.Signer, error) { return nil, errors.New("entropy exhausted") }

func generateUnsupportedKey() (crypto.Signer, error) { return unsupportedSigner{}, nil }

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want a message containing %q", err, want)
	}
}

func TestGenerateTLSReportsAnUnusableDirectory(t *testing.T) {
	skipWhenRoot(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	readOnly := filepath.Join(t.TempDir(), "read-only")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatalf("mkdir read-only: %v", err)
	}

	tests := []struct {
		name string
		dir  string
		want string
	}{
		{name: "below a regular file", dir: filepath.Join(file, "tls"), want: "vaultops: remove"},
		{name: "below a read-only directory", dir: filepath.Join(readOnly, "tls"), want: "vaultops: mkdir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertErrorContains(t, GenerateTLS(tt.dir, testListeners), tt.want)
		})
	}
}

func TestIssueSelfSignedRootCAReportsEachFailingStep(t *testing.T) {
	tests := []struct {
		name        string
		dir         string
		generateKey func() (crypto.Signer, error)
		want        string
	}{
		{name: "key generation", dir: t.TempDir(), generateKey: failKeyGeneration, want: "vaultops: generate example-ca key"},
		{name: "certificate creation", dir: t.TempDir(), generateKey: generateUnsupportedKey, want: "vaultops: create example-ca certificate"},
		{name: "key file write", dir: filepath.Join(t.TempDir(), "absent"), generateKey: generateECP384Key, want: "vaultops: create "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := issueSelfSignedRootCA(tt.dir, "example-ca", "Example CA", tt.generateKey)
			assertErrorContains(t, err, tt.want)
		})
	}
}

func TestIssueListenerCertReportsEachFailingStep(t *testing.T) {
	ca, err := issueSelfSignedRootCA(t.TempDir(), "example-ca", "Example CA", generateECP384Key)
	if err != nil {
		t.Fatalf("issueSelfSignedRootCA: %v", err)
	}
	foreignKey, err := generateECP384Key()
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}

	tests := []struct {
		name        string
		ca          signingCA
		generateKey func() (crypto.Signer, error)
		want        string
	}{
		{name: "key generation", ca: ca, generateKey: failKeyGeneration, want: "vaultops: generate example-listener key"},
		{name: "a CA key which does not match the CA certificate", ca: signingCA{cert: ca.cert, key: foreignKey}, generateKey: generateECP384Key, want: "vaultops: create example-listener certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := &x509.Certificate{Subject: pkix.Name{CommonName: "example-listener"}}
			assertErrorContains(t, issueListenerCert(t.TempDir(), "example-listener", template, tt.ca, tt.generateKey), tt.want)
		})
	}
}

func TestWriteCertificatePairRefusesAKeyWithoutPKCS8Form(t *testing.T) {
	dir := t.TempDir()
	err := writeCertificatePair(dir, "example", []byte("certificate"), unsupportedSigner{})
	assertErrorContains(t, err, "vaultops: marshal example key")
	if _, statErr := os.Stat(filepath.Join(dir, "example.pem")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("example.pem stat error = %v, want no certificate without its key", statErr)
	}
}
