package vaultops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// File names below vault/tls. Each certificate <name>.pem pairs with the private key <name>-key.pem.
const (
	tlsNameMLDSACA  = "ca-ml-dsa-87"
	tlsNameECCA     = "ca-ec-p384"
	tlsNameLoopback = "loopback"
	tlsNamePublish  = "publish"
)

// Listeners holds the network IP addresses for Vault listener certificates.
type Listeners struct {
	Loopback net.IP
	Publish  net.IP
}

// signingCA holds a parsed CA certificate with the CA private key which signs subordinate certificates.
type signingCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// GenerateTLS creates the two CAs and the two listener certificates under the target directory.
// The publish chain MUST stay EC P-384 until every guest verifier accepts ML-DSA.
func GenerateTLS(dir string, listeners Listeners) error {
	if listeners.Loopback == nil || listeners.Publish == nil {
		return errors.New("vaultops: the listener certificates need valid loopback and publish IP addresses")
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("vaultops: remove %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("vaultops: mkdir %s: %w", dir, err)
	}

	mldsaCA, err := issueSelfSignedRootCA(dir, tlsNameMLDSACA, "Vault Transport Root CA ML-DSA-87", generateMLDSA87Key)
	if err != nil {
		return err
	}
	ecCA, err := issueSelfSignedRootCA(dir, tlsNameECCA, "Vault Transport Root CA EC P-384", generateECP384Key)
	if err != nil {
		return err
	}
	loopback := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "localhost"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{listeners.Loopback},
	}
	if err := issueListenerCert(dir, tlsNameLoopback, loopback, mldsaCA, generateMLDSA87Key); err != nil {
		return err
	}
	publish := &x509.Certificate{
		Subject:     pkix.Name{CommonName: listeners.Publish.String()},
		IPAddresses: []net.IP{listeners.Publish},
	}
	if err := issueListenerCert(dir, tlsNamePublish, publish, ecCA, generateECP384Key); err != nil {
		return err
	}
	return nil
}

func generateMLDSA87Key() (crypto.Signer, error) {
	return mldsa.GenerateKey(mldsa.MLDSA87())
}

func generateECP384Key() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func issueSelfSignedRootCA(dir, name, commonName string, generateKey func() (crypto.Signer, error)) (signingCA, error) {
	key, err := generateKey()
	if err != nil {
		return signingCA{}, fmt.Errorf("vaultops: generate %s key: %w", name, err)
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := createCertificate(name, template, template, key.Public(), key)
	if err != nil {
		return signingCA{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return signingCA{}, fmt.Errorf("vaultops: parse %s certificate: %w", name, err)
	}
	if err := writeCertificatePair(dir, name, der, key); err != nil {
		return signingCA{}, err
	}
	return signingCA{cert: cert, key: key}, nil
}

func issueListenerCert(dir, name string, template *x509.Certificate, ca signingCA, generateKey func() (crypto.Signer, error)) error {
	key, err := generateKey()
	if err != nil {
		return fmt.Errorf("vaultops: generate %s key: %w", name, err)
	}
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	der, err := createCertificate(name, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		return err
	}
	return writeCertificatePair(dir, name, der, key)
}

// createCertificate backdates NotBefore by five minutes to tolerate clock skew between the host and its guests.
func createCertificate(name string, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	serial, err := generateCertificateSerial()
	if err != nil {
		return nil, err
	}
	template.SerialNumber = serial
	template.NotBefore = time.Now().Add(-5 * time.Minute)
	template.NotAfter = time.Now().AddDate(1, 0, 0)
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("vaultops: create %s certificate: %w", name, err)
	}
	return der, nil
}

func generateCertificateSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("vaultops: generate certificate serial: %w", err)
	}
	return serial, nil
}

// writeCertificatePair stores the key as PKCS #8, which Go writes in the seed-only form for ML-DSA.
// Vault and OpenSSL read the seed-only form, while Go rejects the expanded ML-DSA private key form.
func writeCertificatePair(dir, name string, der []byte, key crypto.Signer) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("vaultops: marshal %s key: %w", name, err)
	}
	if err := writePEMFile(filepath.Join(dir, name+"-key.pem"), "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return writePEMFile(filepath.Join(dir, name+".pem"), "CERTIFICATE", der, 0o644)
}

func writePEMFile(path, blockType string, der []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("vaultops: create %s: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("vaultops: close %s: %w", path, closeErr)
		}
	}()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("vaultops: pem encode %s: %w", path, err)
	}
	return nil
}
