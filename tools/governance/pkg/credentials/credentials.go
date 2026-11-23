// Package credentials parses rotatable service admin credentials from workstation-topology.yaml.
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

var fullComplexityClasses = []secretgen.CharClass{
	secretgen.Upper, secretgen.Lower, secretgen.Digit, secretgen.Special,
}

// Config is the service_admin_passwords list of workstation-topology.yaml.
type Config struct {
	Credentials []credentialConfig `yaml:"service_admin_passwords"`
}

// Credential pairs a lookup Key with the secretrotate.Spec rotating the named secret.
type Credential struct {
	Key           string
	AdminUsername string
	Spec          secretrotate.Spec
}

type credentialConfig struct {
	Key          string        `yaml:"key"`
	VaultKVMount string        `yaml:"vault_kv_mount"`
	VaultKVPath  string        `yaml:"vault_kv_path"`
	Length       int           `yaml:"length"`
	Service      serviceConfig `yaml:"service"`
}

type serviceConfig struct {
	Mechanism              string `yaml:"mechanism"`
	RotateEndpoint         string `yaml:"rotate_endpoint"`
	VerifyEndpoint         string `yaml:"verify_endpoint"`
	AdminUsername          string `yaml:"admin_username"`
	FactoryDefaultPassword string `yaml:"factory_default_password"`
}

// Load parses service_admin_passwords of the YAML file at path. A missing file returns a zero Config and no error.
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

// Lookup finds a Credential by Key among creds.
func Lookup(creds []Credential, key string) (Credential, bool) {
	for _, cred := range creds {
		if cred.Key == key {
			return cred, true
		}
	}
	return Credential{}, false
}

// BuildCredentials converts each configured entry into a Credential. Duplicate derived Vault fields return an error.
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

func formatVaultFieldName(key string) string {
	return strings.ReplaceAll(key, "-", "_")
}

func resolveServiceFuncs(s serviceConfig) (secretrotate.DeployFunc, secretrotate.VerifyFunc, error) {
	switch s.Mechanism {
	case "http_form":
		if s.VerifyEndpoint == "" {
			return nil, nil, fmt.Errorf("http_form requires verify_endpoint because rotation observes the live credential before any change")
		}
		form := httprotate.FormSpec{
			URL:           s.RotateEndpoint,
			VerifyURL:     s.VerifyEndpoint,
			AdminUsername: s.AdminUsername,
		}
		return form.Deploy, form.Verify, nil
	default:
		return nil, nil, fmt.Errorf("unknown service mechanism %q", s.Mechanism)
	}
}

func (c credentialConfig) toCredential() (Credential, error) {
	deploy, verify, err := resolveServiceFuncs(c.Service)
	if err != nil {
		return Credential{}, fmt.Errorf("credentials: %s: %w", c.Key, err)
	}
	return Credential{
		Key:           c.Key,
		AdminUsername: c.Service.AdminUsername,
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
