package vaultops

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateTLSProducesAValidChain(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root}

	if err := GenerateTLS(context.Background(), p, discardOut()); err != nil {
		t.Fatalf("GenerateTLS: %v", err)
	}

	caCert := loadCert(t, filepath.Join(root, "vault", "tls", "ca.pem"))
	serverCert := loadCert(t, filepath.Join(root, "vault", "tls", "vault.pem"))

	if !caCert.IsCA {
		t.Error("ca.pem is not marked as a CA certificate")
	}
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("vault.pem is not signed by ca.pem: %v", err)
	}

	wantSAN := map[string]bool{"127.0.0.1": false, "172.16.0.1": false}
	for _, ip := range serverCert.IPAddresses {
		if _, ok := wantSAN[ip.String()]; ok {
			wantSAN[ip.String()] = true
		}
	}
	for ip, found := range wantSAN {
		if !found {
			t.Errorf("vault.pem is missing IP SAN %s", ip)
		}
	}

	assertMode(t, filepath.Join(root, "vault", "tls", "ca-key.pem"), 0o600)
	assertMode(t, filepath.Join(root, "vault", "tls", "vault-key.pem"), 0o600)
	assertMode(t, filepath.Join(root, "vault", "tls", "ca.pem"), 0o644)

	assertCertClockSkewTolerant(t, "ca.pem", caCert)
	assertCertClockSkewTolerant(t, "vault.pem", serverCert)
}

func assertCertClockSkewTolerant(t *testing.T, name string, cert *x509.Certificate) {
	t.Helper()
	skew := time.Since(cert.NotBefore)
	if skew < 4*time.Minute || skew > 6*time.Minute {
		t.Errorf("%s NotBefore is %v before now, want ~5m of clock-skew backdating", name, skew)
	}
	validity := cert.NotAfter.Sub(cert.NotBefore)
	wantMin, wantMax := 364*24*time.Hour, 366*24*time.Hour
	if validity < wantMin || validity > wantMax {
		t.Errorf("%s validity period = %v, want ~1 year", name, validity)
	}
}

func TestGenerateTLSIsIdempotentAcrossRuns(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root}
	out := discardOut()

	if err := GenerateTLS(context.Background(), p, out); err != nil {
		t.Fatalf("first GenerateTLS: %v", err)
	}
	first := loadCert(t, filepath.Join(root, "vault", "tls", "ca.pem"))

	if err := GenerateTLS(context.Background(), p, out); err != nil {
		t.Fatalf("second GenerateTLS: %v", err)
	}
	second := loadCert(t, filepath.Join(root, "vault", "tls", "ca.pem"))

	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Error("two runs produced the same serial number; each run should mint fresh material")
	}
}
