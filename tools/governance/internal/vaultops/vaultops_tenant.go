package vaultops

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// ErrInvalidTenant reports a tenant code which is not a lowercase hyphenated owner code.
var ErrInvalidTenant = errors.New("vaultops: invalid tenant code")

// ErrWrapConsumed reports a wrapping token which another party unwrapped first.
var ErrWrapConsumed = errors.New("vaultops: wrapping token already consumed")

const (
	defaultTenantMount   = "approle"
	defaultTenantWrapTTL = 60 * time.Second
	tenantOperatorSuffix = "-terraform-operator"
)

// The pattern also rejects path separators and dot segments, since the code becomes a Vault path segment.
var tenantCodePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// TenantSessionRequest names the tenant whose Terraform operator role opens the session.
type TenantSessionRequest struct {
	// Tenant is the owner code, such as meta-platform.
	Tenant string
	// Mount is the AppRole mount path. An empty Mount selects approle.
	Mount string
	// WrapTTL bounds the wrapping token and the secret ID. A zero WrapTTL selects 60 seconds.
	WrapTTL time.Duration
}

// TenantSession holds the tenant token which the session shell receives.
type TenantSession struct {
	Token string
}

// OpenTenantSession mints a single-use wrapped secret ID with the operator client, unwraps the secret ID, and logs in
// as the tenant Terraform operator.
func OpenTenantSession(ctx context.Context, admin *vaultapi.Client, req TenantSessionRequest) (TenantSession, error) {
	if !tenantCodePattern.MatchString(req.Tenant) {
		return TenantSession{}, fmt.Errorf("%w: %q", ErrInvalidTenant, req.Tenant)
	}
	if admin == nil {
		return TenantSession{}, errors.New("vaultops: nil admin client")
	}
	mount := cmp.Or(req.Mount, defaultTenantMount)
	ttl := formatVaultTTL(cmp.Or(req.WrapTTL, defaultTenantWrapTTL))
	rolePath := "auth/" + mount + "/role/" + req.Tenant + tenantOperatorSuffix

	roleID, err := readRoleID(ctx, admin, rolePath)
	if err != nil {
		return TenantSession{}, err
	}
	wrappingToken, err := mintWrappedSecretID(ctx, admin, rolePath, ttl)
	if err != nil {
		return TenantSession{}, err
	}
	secretID, err := unwrapSecretID(ctx, admin, wrappingToken)
	if err != nil {
		return TenantSession{}, err
	}
	return loginTenant(ctx, admin, vaultclient.AppRoleAuth{Mount: mount, RoleID: roleID, SecretID: secretID})
}

// ListTenantCodes returns the sorted tenant codes whose Terraform operator role exists on the AppRole mount.
// An empty mount selects approle.
func ListTenantCodes(ctx context.Context, admin *vaultapi.Client, mount string) ([]string, error) {
	if admin == nil {
		return nil, errors.New("vaultops: nil admin client")
	}
	path := "auth/" + cmp.Or(mount, defaultTenantMount) + "/role"
	secret, err := admin.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vaultops: list tenant roles of %s: %w", path, err)
	}
	codes := []string{}
	if secret == nil {
		return codes, nil
	}
	keys, _ := secret.Data["keys"].([]interface{})
	for _, key := range keys {
		role, _ := key.(string)
		code, isOperator := strings.CutSuffix(role, tenantOperatorSuffix)
		if isOperator && tenantCodePattern.MatchString(code) {
			codes = append(codes, code)
		}
	}
	slices.Sort(codes)
	return codes, nil
}

// TenantShell runs the session shell. Base is the environment which BuildTenantSessionEnv rewrites for the shell.
type TenantShell struct {
	Base []string
	Run  func(ctx context.Context, env []string) error
}

// RunTenantSession opens a tenant session, runs the shell with the session environment, and revokes the session token
// after the shell exits, even when the shell fails or ctx is canceled.
func RunTenantSession(ctx context.Context, p Paths, admin *vaultapi.Client, req TenantSessionRequest, out *ui.Printer, shell TenantShell) error {
	session, err := OpenTenantSession(ctx, admin, req)
	if err != nil {
		return err
	}
	out.Print(ui.OK, fmt.Sprintf("Tenant session for %s opened. Exit the shell to revoke the token.", req.Tenant))

	runErr := shell.Run(ctx, BuildTenantSessionEnv(shell.Base, session, p))
	// The revoke outlives a canceled ctx, since an unrevoked token stays valid until its TTL ends.
	revokeErr := RevokeTenantSession(context.WithoutCancel(ctx), admin, session)
	if revokeErr == nil {
		out.Print(ui.OK, "Tenant session token revoked.")
	}
	return errors.Join(runErr, revokeErr)
}

// RevokeTenantSession revokes the session token through revoke-self.
func RevokeTenantSession(ctx context.Context, base *vaultapi.Client, s TenantSession) error {
	if s.Token == "" {
		return errors.New("vaultops: empty tenant session token")
	}
	client, err := cloneWithToken(base, s.Token)
	if err != nil {
		return err
	}
	if err := client.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
		return fmt.Errorf("vaultops: revoke tenant session: %w", err)
	}
	return nil
}

// BuildTenantSessionEnv returns base with VAULT_TOKEN, VAULT_ADDR, and VAULT_CACERT replaced by the session and the
// Bastion Vault values of p.
func BuildTenantSessionEnv(base []string, s TenantSession, p Paths) []string {
	env := make([]string, 0, len(base)+3)
	for _, entry := range base {
		if hasVaultSessionKey(entry) {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"VAULT_TOKEN="+s.Token,
		"VAULT_ADDR="+p.resolveBastionAddr(),
		"VAULT_CACERT="+p.resolveCACertFile(),
	)
}

func hasVaultSessionKey(entry string) bool {
	for _, key := range []string{"VAULT_TOKEN=", "VAULT_ADDR=", "VAULT_CACERT="} {
		if strings.HasPrefix(entry, key) {
			return true
		}
	}
	return false
}

func formatVaultTTL(d time.Duration) string {
	return fmt.Sprintf("%ds", int64(d/time.Second))
}

func readRoleID(ctx context.Context, admin *vaultapi.Client, rolePath string) (string, error) {
	secret, err := admin.Logical().ReadWithContext(ctx, rolePath+"/role-id")
	if err != nil {
		return "", fmt.Errorf("vaultops: read role id of %s: %w", rolePath, err)
	}
	return readDataString(secret, "role_id", rolePath+"/role-id")
}

// mintWrappedSecretID requests a secret ID valid for one login, which Vault returns only inside a wrapping token.
func mintWrappedSecretID(ctx context.Context, admin *vaultapi.Client, rolePath, ttl string) (string, error) {
	minter, err := cloneWithToken(admin, admin.Token())
	if err != nil {
		return "", err
	}
	minter.SetWrappingLookupFunc(func(string, string) string { return ttl })
	secret, err := minter.Logical().WriteWithContext(ctx, rolePath+"/secret-id", map[string]interface{}{
		"num_uses": 1,
		"ttl":      ttl,
	})
	if err != nil {
		return "", fmt.Errorf("vaultops: mint secret id of %s: %w", rolePath, err)
	}
	if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" {
		return "", fmt.Errorf("vaultops: secret id of %s returned without response wrapping", rolePath)
	}
	return secret.WrapInfo.Token, nil
}

// unwrapSecretID fails closed with ErrWrapConsumed when Vault rejects the wrapping token.
func unwrapSecretID(ctx context.Context, base *vaultapi.Client, wrappingToken string) (string, error) {
	unwrapper, err := cloneWithToken(base, "")
	if err != nil {
		return "", err
	}
	secret, err := unwrapper.Logical().UnwrapWithContext(ctx, wrappingToken)
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == http.StatusBadRequest {
		return "", fmt.Errorf("%w: %w", ErrWrapConsumed, err)
	}
	if err != nil {
		return "", fmt.Errorf("vaultops: unwrap secret id: %w", err)
	}
	return readDataString(secret, "secret_id", "sys/wrapping/unwrap")
}

// loginTenant logs in through a token-free client.
func loginTenant(ctx context.Context, base *vaultapi.Client, auth vaultclient.AppRoleAuth) (TenantSession, error) {
	client, err := cloneWithToken(base, "")
	if err != nil {
		return TenantSession{}, err
	}
	token, err := auth.Login(ctx, client)
	if err != nil {
		return TenantSession{}, fmt.Errorf("vaultops: tenant login: %w", err)
	}
	return TenantSession{Token: token}, nil
}

// cloneWithToken returns a copy of base which holds token alone, since Clone picks up the ambient VAULT_TOKEN.
func cloneWithToken(base *vaultapi.Client, token string) (*vaultapi.Client, error) {
	if base == nil {
		return nil, errors.New("vaultops: nil base client")
	}
	client, err := base.Clone()
	if err != nil {
		return nil, fmt.Errorf("vaultops: clone client: %w", err)
	}
	client.ClearToken()
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}

func readDataString(secret *vaultapi.Secret, field, path string) (string, error) {
	if secret == nil {
		return "", fmt.Errorf("vaultops: empty response from %s", path)
	}
	value, ok := secret.Data[field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("vaultops: %s missing from %s", field, path)
	}
	return value, nil
}
