package vaultops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func generateTestTLS(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault", "tls")
	if err := GenerateTLS(dir, testListeners); err != nil {
		t.Fatalf("GenerateTLS: %v", err)
	}
	return dir
}

func TestGenerateTLSIsIdempotentAcrossRuns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault", "tls")
	if err := GenerateTLS(dir, testListeners); err != nil {
		t.Fatalf("first GenerateTLS: %v", err)
	}
	first := loadCert(t, filepath.Join(dir, tlsNameMLDSACA+".pem"))

	if err := GenerateTLS(dir, testListeners); err != nil {
		t.Fatalf("second GenerateTLS: %v", err)
	}
	second := loadCert(t, filepath.Join(dir, tlsNameMLDSACA+".pem"))

	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Error("two runs produced the same serial number; each run should mint fresh material")
	}
}

func TestGenerateTLSRequiresTheListenerAddresses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vault", "tls")
	err := GenerateTLS(dir, Listeners{})
	if err == nil {
		t.Fatal("GenerateTLS error = nil, want a refusal without listener addresses")
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("vault/tls stat error = %v, want an absent directory after the refusal", statErr)
	}
}

func TestGenerateTLSIssuesEachCertificateWithItsAlgorithm(t *testing.T) {
	tlsDir := generateTestTLS(t)

	cases := []struct {
		name      string
		issuer    string
		isCA      bool
		signature x509.SignatureAlgorithm
		ips       []string
		dnsNames  []string
	}{
		{name: tlsNameMLDSACA, issuer: tlsNameMLDSACA, isCA: true, signature: x509.MLDSA87},
		{name: tlsNameECCA, issuer: tlsNameECCA, isCA: true, signature: x509.ECDSAWithSHA384},
		{name: tlsNameLoopback, issuer: tlsNameMLDSACA, signature: x509.MLDSA87, ips: []string{testListeners.Loopback.String()}, dnsNames: []string{"localhost"}},
		{name: tlsNamePublish, issuer: tlsNameECCA, signature: x509.ECDSAWithSHA384, ips: []string{testListeners.Publish.String()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := loadCert(t, filepath.Join(tlsDir, c.name+".pem"))
			issuer := loadCert(t, filepath.Join(tlsDir, c.issuer+".pem"))

			if cert.IsCA != c.isCA {
				t.Errorf("IsCA = %v, want %v", cert.IsCA, c.isCA)
			}
			if cert.SignatureAlgorithm != c.signature {
				t.Errorf("signature algorithm = %v, want %v", cert.SignatureAlgorithm, c.signature)
			}
			if err := cert.CheckSignatureFrom(issuer); err != nil {
				t.Errorf("certificate is not signed by %s: %v", c.issuer, err)
			}
			ips := make([]string, 0, len(cert.IPAddresses))
			for _, ip := range cert.IPAddresses {
				ips = append(ips, ip.String())
			}
			if !slices.Equal(ips, c.ips) {
				t.Errorf("IP SANs = %v, want %v", ips, c.ips)
			}
			if !slices.Equal(cert.DNSNames, c.dnsNames) {
				t.Errorf("DNS SANs = %v, want %v", cert.DNSNames, c.dnsNames)
			}
			if !c.isCA && cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("key usage = %v, want DigitalSignature alone", cert.KeyUsage)
			}

			key := loadPKCS8Key(t, filepath.Join(tlsDir, c.name+"-key.pem"))
			if !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(cert.PublicKey) {
				t.Errorf("%s-key.pem does not hold the private key of %s.pem", c.name, c.name)
			}
			assertMode(t, filepath.Join(tlsDir, c.name+"-key.pem"), 0o600)
			assertMode(t, filepath.Join(tlsDir, c.name+".pem"), 0o644)
			assertCertClockSkewTolerant(t, c.name, cert)
		})
	}
}

func TestGenerateTLSUsesMLDSA87AndECP384Keys(t *testing.T) {
	tlsDir := generateTestTLS(t)

	for _, name := range []string{tlsNameMLDSACA, tlsNameLoopback} {
		pub, ok := loadCert(t, filepath.Join(tlsDir, name+".pem")).PublicKey.(*mldsa.PublicKey)
		if !ok || pub.Parameters() != mldsa.MLDSA87() {
			t.Errorf("%s public key, want ML-DSA-87", name)
		}
	}
	for _, name := range []string{tlsNameECCA, tlsNamePublish} {
		pub, ok := loadCert(t, filepath.Join(tlsDir, name+".pem")).PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P384() {
			t.Errorf("%s public key, want ECDSA P-384", name)
		}
	}
}

// TestGenerateTLSWritesSeedOnlyMLDSAKeys ensures ML-DSA-87 private keys use seed-only encoding,
// which is required for Go since Go rejects the expanded form.
func TestGenerateTLSWritesSeedOnlyMLDSAKeys(t *testing.T) {
	tlsDir := generateTestTLS(t)

	for _, name := range []string{tlsNameMLDSACA, tlsNameLoopback} {
		var info struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
		}
		if _, err := asn1.Unmarshal(readPEMBlock(t, filepath.Join(tlsDir, name+"-key.pem")), &info); err != nil {
			t.Fatalf("%s-key.pem: unmarshal PKCS #8: %v", name, err)
		}
		if len(info.PrivateKey) != 2+mldsa.PrivateKeySize || info.PrivateKey[0] != 0x80 || info.PrivateKey[1] != mldsa.PrivateKeySize {
			t.Errorf("%s-key.pem holds %d private key bytes, want the [0] seed of %d bytes alone", name, len(info.PrivateKey), mldsa.PrivateKeySize)
		}
	}
}

func TestGenerateTLSSeparatesTheTwoChains(t *testing.T) {
	tlsDir := generateTestTLS(t)

	cases := []struct {
		leaf, root, host string
		wantVerified     bool
	}{
		{leaf: tlsNameLoopback, root: tlsNameMLDSACA, host: testListeners.Loopback.String(), wantVerified: true},
		{leaf: tlsNamePublish, root: tlsNameECCA, host: testListeners.Publish.String(), wantVerified: true},
		{leaf: tlsNameLoopback, root: tlsNameECCA, host: testListeners.Loopback.String()},
		{leaf: tlsNamePublish, root: tlsNameMLDSACA, host: testListeners.Publish.String()},
	}
	for _, c := range cases {
		t.Run(c.leaf+" under "+c.root, func(t *testing.T) {
			roots := x509.NewCertPool()
			roots.AddCert(loadCert(t, filepath.Join(tlsDir, c.root+".pem")))
			_, err := loadCert(t, filepath.Join(tlsDir, c.leaf+".pem")).Verify(x509.VerifyOptions{Roots: roots, DNSName: c.host})
			if (err == nil) != c.wantVerified {
				t.Errorf("Verify error = %v, want verified %v", err, c.wantVerified)
			}
		})
	}
}

func TestGenerateTLSServesTheLoopbackListenerWithMLDSA87(t *testing.T) {
	tlsDir := generateTestTLS(t)

	pair, err := tls.LoadX509KeyPair(filepath.Join(tlsDir, tlsNameLoopback+".pem"), filepath.Join(tlsDir, tlsNameLoopback+"-key.pem"))
	if err != nil {
		t.Fatalf("the loopback pair does not load as Vault loads the pair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() /* WHY: The listener closes after the test reads the result. */ })
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer func() { _ = conn.Close() /* WHY: The handshake result is already sent. */ }()
		done <- conn.(*tls.Conn).Handshake()
	}()

	roots := x509.NewCertPool()
	roots.AddCert(loadCert(t, filepath.Join(tlsDir, tlsNameMLDSACA+".pem")))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("dial the ML-DSA-87 loopback listener: %v", err)
	}
	defer func() { _ = conn.Close() /* WHY: The handshake already succeeded. */ }()
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if got := conn.ConnectionState().PeerCertificates[0].SignatureAlgorithm; got != x509.MLDSA87 {
		t.Errorf("peer signature algorithm = %v, want ML-DSA-87", got)
	}
}

func TestGenerateTLSLoadsThePublishListenerPair(t *testing.T) {
	tlsDir := generateTestTLS(t)

	if _, err := tls.LoadX509KeyPair(filepath.Join(tlsDir, tlsNamePublish+".pem"), filepath.Join(tlsDir, tlsNamePublish+"-key.pem")); err != nil {
		t.Errorf("the publish pair does not load as Vault loads the pair: %v", err)
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

func readPEMBlock(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("%s is not a PKCS #8 PEM block", path)
	}
	return block.Bytes
}

func loadPKCS8Key(t *testing.T, path string) crypto.Signer {
	t.Helper()
	parsed, err := x509.ParsePKCS8PrivateKey(readPEMBlock(t, path))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		t.Fatalf("%s holds %T, want a crypto.Signer", path, parsed)
	}
	return key
}
