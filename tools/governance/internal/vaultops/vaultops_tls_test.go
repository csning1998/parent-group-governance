package vaultops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateTLSIsIdempotentAcrossRuns(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, listenerIPs: testBastion.ListenerIPs()}
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

func TestGenerateTLSProducesAValidChain(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, listenerIPs: testBastion.ListenerIPs()}

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

	wantSAN := map[string]bool{testBastion.LoopbackAddress: false, testBastion.PublishAddress: false}
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

func TestGenerateTLSRequiresTheListenerAddresses(t *testing.T) {
	root := t.TempDir()
	err := GenerateTLS(context.Background(), Paths{ProjectRoot: root}, discardOut())
	if err == nil {
		t.Fatal("GenerateTLS error = nil, want a refusal without the topology addresses")
	}
	if _, statErr := os.Stat(filepath.Join(root, "vault", "tls")); !os.IsNotExist(statErr) {
		t.Errorf("vault/tls stat error = %v, want no directory after the refusal", statErr)
	}
}

func TestGenerateTLSUsesECDSAP256Keys(t *testing.T) {
	root := t.TempDir()
	p := Paths{ProjectRoot: root, listenerIPs: testBastion.ListenerIPs()}

	if err := GenerateTLS(context.Background(), p, discardOut()); err != nil {
		t.Fatalf("GenerateTLS: %v", err)
	}

	tlsDir := filepath.Join(root, "vault", "tls")
	pairs := []struct{ cert, key string }{
		{cert: "ca.pem", key: "ca-key.pem"},
		{cert: "vault.pem", key: "vault-key.pem"},
	}
	for _, pair := range pairs {
		cert := loadCert(t, filepath.Join(tlsDir, pair.cert))
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			t.Errorf("%s public key = %T, want ECDSA P-256", pair.cert, cert.PublicKey)
			continue
		}
		if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Errorf("%s signature algorithm = %v, want ECDSAWithSHA256", pair.cert, cert.SignatureAlgorithm)
		}

		key := loadPKCS8ECDSAKey(t, filepath.Join(tlsDir, pair.key))
		if !key.PublicKey.Equal(pub) {
			t.Errorf("%s does not hold the private key of %s", pair.key, pair.cert)
		}
	}

	// An ECDSA key performs no key encipherment, and the listener needs only signatures.
	serverCert := loadCert(t, filepath.Join(tlsDir, "vault.pem"))
	if serverCert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("vault.pem key usage = %v, want DigitalSignature alone", serverCert.KeyUsage)
	}

	if _, err := tls.LoadX509KeyPair(filepath.Join(tlsDir, "vault.pem"), filepath.Join(tlsDir, "vault-key.pem")); err != nil {
		t.Errorf("the listener pair does not load as Vault loads the pair: %v", err)
	}
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

func loadPKCS8ECDSAKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("%s is not a PKCS #8 PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("%s holds %T, want *ecdsa.PrivateKey", path, parsed)
	}
	return key
}
