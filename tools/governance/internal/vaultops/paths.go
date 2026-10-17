package vaultops

import (
	"path/filepath"
)

// Paths locates filesystem paths which Vault operations read or write.
type Paths struct {
	ProjectRoot string
	Home        string
}

// NewPaths constructs Paths from explicit filesystem roots.
func NewPaths(projectRoot, home string) Paths {
	return Paths{
		ProjectRoot: projectRoot,
		Home:        home,
	}
}

// TLSDir returns the directory where the CAs and listener certificates MUST reside.
func (p Paths) TLSDir() string { return filepath.Join(p.ProjectRoot, "vault", "tls") }

// TransportRootMLDSA87CACertFile returns the certificate file path of the local ML-DSA-87 transport root CA.
func (p Paths) TransportRootMLDSA87CACertFile() string {
	return filepath.Join(p.TLSDir(), tlsNameMLDSACA+".pem")
}

// KeysDir returns the directory where initialization outputs and unseal keys MUST reside.
func (p Paths) KeysDir() string { return filepath.Join(p.ProjectRoot, "vault", "keys") }

// InitFile returns the initialization output JSON file path.
func (p Paths) InitFile() string { return filepath.Join(p.KeysDir(), "init-output.json") }

// UnsealKeyFile returns the raw unseal keys file path.
func (p Paths) UnsealKeyFile() string { return filepath.Join(p.KeysDir(), "unseal.key") }

// RootTokenFile returns the token helper file path ~/.vault-token.
func (p Paths) RootTokenFile() string { return filepath.Join(p.Home, ".vault-token") }
