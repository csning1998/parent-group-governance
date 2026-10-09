package vaultops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

// GenerateTLS creates a fresh CA and server certificate under the vault/tls directory.
func GenerateTLS(ctx context.Context, p Paths, out *ui.Printer) error {
	if len(p.listenerIPs) == 0 {
		return fmt.Errorf("vaultops: the listener certificate needs the Bastion Vault addresses of workstation-topology.yaml")
	}
	resolveTLSDir := p.resolveTLSDir()
	if err := os.RemoveAll(resolveTLSDir); err != nil {
		return fmt.Errorf("vaultops: remove %s: %w", resolveTLSDir, err)
	}
	if err := os.MkdirAll(resolveTLSDir, 0o755); err != nil {
		return fmt.Errorf("vaultops: mkdir %s: %w", resolveTLSDir, err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("vaultops: generate CA key: %w", err)
	}
	caSerial, err := generateCertificateSerial()
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "MetaProvisionVaultCA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("vaultops: create CA certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("vaultops: generate server key: %w", err)
	}
	serverSerial, err := generateCertificateSerial()
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  p.listenerIPs,
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("vaultops: parse CA certificate: %w", err)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("vaultops: create server certificate: %w", err)
	}

	if err := writePrivateKeyFile(filepath.Join(resolveTLSDir, "ca-key.pem"), caKey); err != nil {
		return err
	}
	if err := writePEMFile(filepath.Join(resolveTLSDir, "ca.pem"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	if err := writePrivateKeyFile(filepath.Join(resolveTLSDir, "vault-key.pem"), serverKey); err != nil {
		return err
	}
	if err := writePEMFile(filepath.Join(resolveTLSDir, "vault.pem"), "CERTIFICATE", serverDER, 0o644); err != nil {
		return err
	}

	out.Print(ui.OK, "Bastion Vault TLS Certificates generated.")
	return nil
}

func generateCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("vaultops: generate certificate serial: %w", err)
	}
	return serial, nil
}

func writePEMFile(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("vaultops: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("vaultops: encode %s: %w", path, err)
	}
	return nil
}

// writePrivateKeyFile stores the key as PKCS #8, which Vault and OpenSSL read for every key algorithm.
func writePrivateKeyFile(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("vaultops: marshal %s: %w", path, err)
	}
	return writePEMFile(path, "PRIVATE KEY", der, 0o600)
}
