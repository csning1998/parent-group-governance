package vaultops

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

var testListeners = Listeners{
	Loopback: net.ParseIP("127.0.0.1"),
	Publish:  net.ParseIP("192.0.2.10"),
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

func discardOut() *ui.Printer { return ui.New(io.Discard, io.Discard) }

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s does not contain a PEM block", path)
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", path, err)
	}
	return cert
}

func newTestOperator(t *testing.T, p Paths, address string) *Operator {
	t.Helper()
	var caCertPath string
	if _, err := os.Stat(p.CACertFile()); err == nil {
		caCertPath = p.CACertFile()
	}
	server := vaultclient.Config{
		Address:    address,
		CACertPath: caCertPath,
	}
	op, err := NewOperator(p, server, discardOut())
	if err != nil {
		t.Fatalf("NewOperator: %v", err)
	}
	op.client.SetMaxRetries(0)
	return op
}

func skipWhenRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-bit test when running as root")
	}
}
