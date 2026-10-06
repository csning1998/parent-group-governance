// Package credentials loads a declarative list of rotatable infrastructure secrets from a YAML file.
// Refer to docs/secretrotate-design.md for the design.
package credentials

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/httprotate"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretgen"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

// Credential pairs a lookup Key with the secretrotate.Spec rotating the named secret.
type Credential struct {
	Key  string
	Spec secretrotate.Spec
}

// VaultOverride optionally names a Vault address for a Config caller to connect to instead of
// its own default.
type VaultOverride struct {
	Address string `yaml:"address"`
}

// Config is the parsed form of a credentials YAML file.
type Config struct {
	Vault       VaultOverride      `yaml:"vault"`
	Credentials []credentialConfig `yaml:"credentials"`
}

type serviceConfig struct {
	Mechanism      string `yaml:"mechanism"`
	Endpoint       string `yaml:"endpoint"`
	VerifyEndpoint string `yaml:"verify_endpoint"`
	Login          string `yaml:"login"`

	FactoryDefaultPassword string `yaml:"factory_default_password"`
}

type credentialConfig struct {
	Key          string        `yaml:"key"`
	VaultKVMount string        `yaml:"vault_kv_mount"`
	VaultKVPath  string        `yaml:"vault_kv_path"`
	Length       int           `yaml:"length"`
	Service      serviceConfig `yaml:"service"`
}

var fullComplexityClasses = []secretgen.CharClass{
	secretgen.Upper, secretgen.Lower, secretgen.Digit, secretgen.Special,
}

// resolveServiceFuncs builds the change and the read only validation of one service mechanism.
func resolveServiceFuncs(s serviceConfig) (secretrotate.DeployFunc, secretrotate.VerifyFunc, error) {
	switch s.Mechanism {
	case "http_form":
		if s.VerifyEndpoint == "" {
			return nil, nil, fmt.Errorf("http_form requires verify_endpoint, since rotation observes the live credential before any change")
		}
		form := httprotate.FormSpec{URL: s.Endpoint, VerifyURL: s.VerifyEndpoint, Login: s.Login}
		return form.Deploy, form.Verify, nil
	default:
		return nil, nil, fmt.Errorf("unknown service mechanism %q", s.Mechanism)
	}
}

func formatVaultFieldName(key string) string {
	return strings.ReplaceAll(key, "-", "_")
}

func (c credentialConfig) toCredential() (Credential, error) {
	deploy, verify, err := resolveServiceFuncs(c.Service)
	if err != nil {
		return Credential{}, fmt.Errorf("credentials: %s: %w", c.Key, err)
	}
	return Credential{
		Key: c.Key,
		Spec: secretrotate.Spec{
			Mount:                  c.VaultKVMount,
			Path:                   c.VaultKVPath,
			Field:                  formatVaultFieldName(c.Key),
			Length:                 c.Length,
			Classes:                fullComplexityClasses,
			Deploy:                 deploy,
			Verify:                 verify,
			FactoryDefaultPassword: c.Service.FactoryDefaultPassword,
		},
	}, nil
}

// Load parses a credentials YAML file at path. A missing file returns a zero Config and no error.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("credentials: read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("credentials: parse %s: %w", path, err)
	}
	return cfg, nil
}

// BuildCredentials converts every entry in Config.Credentials into a Credential, rejecting two keys
// whose derived Vault location collides.
func (c Config) BuildCredentials() ([]Credential, error) {
	creds := make([]Credential, 0, len(c.Credentials))
	owners := make(map[string]string, len(c.Credentials))
	for _, raw := range c.Credentials {
		cred, err := raw.toCredential()
		if err != nil {
			return nil, err
		}
		location := cred.Spec.Mount + "/" + cred.Spec.Path + "#" + cred.Spec.Field
		if owner, collides := owners[location]; collides {
			return nil, fmt.Errorf("credentials: %s and %s both resolve to Vault field %s", owner, cred.Key, location)
		}
		owners[location] = cred.Key
		creds = append(creds, cred)
	}
	return creds, nil
}

// Lookup finds a Credential by Key among creds.
func Lookup(creds []Credential, key string) (Credential, bool) {
	for _, cred := range creds {
		if cred.Key == key {
			return cred, true
		}
	}
	return Credential{}, false
}
