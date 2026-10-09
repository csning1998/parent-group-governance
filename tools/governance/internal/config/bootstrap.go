package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

var hostTools = []requiredTool{
	{"terraform", "HashiCorp Terraform"},
	{"vault", "HashiCorp Vault"},
	{"ansible", "Red Hat Ansible"},
}

// HostFacts holds the operator identity used by Compose ${HOST_UID}:${HOST_GID}.
type HostFacts struct {
	CurrentUID   int
	CurrentGID   int
	CurrentUname string
}

// RandomToken represents a high-entropy cryptographically random string.
type RandomToken string

// ToolCheck reports whether one required tool is installed.
type ToolCheck struct {
	Group     string
	Name      string
	Installed bool
}

type requiredTool struct {
	Cmd  string
	Name string
}

// BootstrapEnv initializes or updates root/.env with host identity and Vault defaults.
func BootstrapEnv(root string, out *ui.Printer) (*Env, error) {
	envPath := filepath.Join(root, ".env")
	facts, err := DetectHostFacts()
	if err != nil {
		return nil, err
	}

	e, err := Load(envPath)
	if err != nil {
		return nil, err
	}

	_, statErr := os.Stat(envPath)
	isNewFile := os.IsNotExist(statErr)

	if isNewFile {
		out.Print(ui.Info, "Creating new .env file...")
		if err := populateNewEnv(e, root, facts); err != nil {
			return nil, err
		}
	} else if err := patchExistingEnv(e, root, facts, out); err != nil {
		return nil, err
	}

	if err := e.Save(); err != nil {
		return nil, err
	}
	return e, nil
}

// DetectHostFacts looks up the current user numeric identity.
func DetectHostFacts() (HostFacts, error) {
	var facts HostFacts
	u, err := user.Current()
	if err != nil {
		return facts, fmt.Errorf("config: lookup current user: %w", err)
	}
	facts.CurrentUname = u.Username
	if uid, err := strconv.Atoi(u.Uid); err == nil {
		facts.CurrentUID = uid
	}
	if gid, err := strconv.Atoi(u.Gid); err == nil {
		facts.CurrentGID = gid
	}
	return facts, nil
}

// VerifyHostEnvironment validates Terraform, Vault, and Ansible against PATH.
func VerifyHostEnvironment() []ToolCheck {
	var checks []ToolCheck
	for _, t := range hostTools {
		_, err := exec.LookPath(t.Cmd)
		checks = append(checks, ToolCheck{"Host IaC tools", t.Name, err == nil})
	}
	return checks
}

// generateRandomToken returns a random URL-safe base64 token decoded from byteLength bytes of crypto/rand output.
func generateRandomToken(byteLength int) (RandomToken, error) {
	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("config: generate random token: %w", err)
	}
	return RandomToken(base64.RawURLEncoding.EncodeToString(buf)), nil
}

// patchExistingEnv refreshes host-identity fields on every run and backfills only the fields
// an existing .env file is still missing.
func patchExistingEnv(e *Env, root string, facts HostFacts, out *ui.Printer) error {
	e.Set(KeyHostUID, strconv.Itoa(facts.CurrentUID))
	e.Set(KeyHostGID, strconv.Itoa(facts.CurrentGID))
	e.Set(KeyProjectRoot, root)
	if e.Get(KeySonarQubeDBPassword) == "" {
		sonarDBPassword, err := generateRandomToken(24)
		if err != nil {
			return err
		}
		out.Print(ui.Info, "Generated SONARQUBE_DB_PASSWORD.")
		e.Set(KeySonarQubeDBPassword, string(sonarDBPassword))
	}
	return nil
}

// populateNewEnv sets every default field a freshly created .env file needs, unconditionally.
func populateNewEnv(e *Env, root string, facts HostFacts) error {
	sonarDBPassword, err := generateRandomToken(24)
	if err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{KeyProjectRoot, root},
		{KeyHostUID, strconv.Itoa(facts.CurrentUID)},
		{KeyHostGID, strconv.Itoa(facts.CurrentGID)},
		{KeyUname, facts.CurrentUname},
		{KeyUhome, "${HOME}"},
		{KeySonarQubeDBPassword, string(sonarDBPassword)},
	} {
		e.Set(kv[0], kv[1])
	}
	return nil
}
