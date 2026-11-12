package vaultops

import (
	"crypto/x509"
	"net"
	"path/filepath"
	"slices"
	"testing"
)

func TestEnsurePublishCertCoversAddsTheAddressOnce(t *testing.T) {
	tlsDir := generateTestTLS(t)
	publishPath := filepath.Join(tlsDir, tlsNamePublish+".pem")
	address := net.ParseIP("192.0.2.1")

	issued, err := EnsurePublishCertCovers(tlsDir, address)
	if err != nil || !issued {
		t.Fatalf("EnsurePublishCertCovers = %v, %v, want a reissued publish certificate", issued, err)
	}
	cert := loadCert(t, publishPath)
	containsIP := func(ip net.IP) bool { return slices.ContainsFunc(cert.IPAddresses, ip.Equal) }
	if len(cert.IPAddresses) != 2 || !containsIP(testListeners.Publish) || !containsIP(address) {
		t.Errorf("publish SAN = %v, want the publish address and %s", cert.IPAddresses, address)
	}
	roots := x509.NewCertPool()
	roots.AddCert(loadCert(t, filepath.Join(tlsDir, tlsNameECCA+".pem")))
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("verify against the EC P-384 CA: %v", err)
	}
	assertMode(t, filepath.Join(tlsDir, tlsNamePublish+"-key.pem"), 0o600)

	issued, err = EnsurePublishCertCovers(tlsDir, address)
	if err != nil || issued {
		t.Fatalf("second EnsurePublishCertCovers = %v, %v, want no new certificate", issued, err)
	}
	if again := loadCert(t, publishPath); !again.Equal(cert) {
		t.Error("the second call replaced a publish certificate which names the address")
	}
}
