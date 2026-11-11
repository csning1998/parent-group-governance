// Package pkipathlen verifies Path Length Constraint enforcement across Vault PKI intermediate certificate authorities.
package pkipathlen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

const rootToken = "pathlen-test"

// devVault provides an isolated, ephemeral Vault development server instance for integration verification.
type devVault struct {
	address string
	client  *http.Client
}

func startDevVault(t *testing.T) *devVault {
	t.Helper()
	binary, err := exec.LookPath("vault")
	if err != nil {
		t.Skip("the vault binary is absent from PATH")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "server", "-dev", "-dev-root-token-id="+rootToken, "-dev-listen-address="+address)
	// Execution environments isolate operator configuration by clearing VAULT_* variables and assigning a transient HOME directory.
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	v := &devVault{address: "http://" + address, client: &http.Client{Timeout: 10 * time.Second}}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := v.client.Get(v.address + "/v1/sys/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return v
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Vault dev server at %s is not ready: %v", v.address, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// write transmits an HTTP POST request to the specified endpoint, returning parsed payload data or API error diagnostics.
func (v *devVault) write(t *testing.T, path string, body map[string]any) (map[string]any, error) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, v.address+"/v1/"+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", rootToken)
	resp, err := v.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var decoded struct {
		Data   map[string]any `json:"data"`
		Errors []string       `json:"errors"`
	}
	if resp.ContentLength != 0 {
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode the response of %s: %v", path, err)
		}
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("%s returned %d: %v", path, resp.StatusCode, decoded.Errors)
	}
	return decoded.Data, nil
}

func (v *devVault) mustWrite(t *testing.T, path string, body map[string]any) map[string]any {
	t.Helper()
	data, err := v.write(t, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// mountIntermediate enables a PKI secrets engine at the specified mount path and generates an intermediate CA CSR.
func (v *devVault) mountIntermediate(t *testing.T, mount string) string {
	t.Helper()
	v.mustWrite(t, "sys/mounts/"+mount, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}})
	data := v.mustWrite(t, mount+"/intermediate/generate/internal", map[string]any{
		"common_name": mount, "key_type": "ec", "key_bits": 384,
	})
	csr, ok := data["csr"].(string)
	if !ok {
		t.Fatalf("%s returned no CSR", mount)
	}
	return csr
}

func TestSignIntermediateEnforcesTheMaxPathLengthOfTheIssuer(t *testing.T) {
	cases := map[string]struct {
		maxPathLength int
		wantRejected  bool
	}{
		"path length zero rejects a subordinate CA": {maxPathLength: 0, wantRejected: true},
		"path length one admits a subordinate CA":   {maxPathLength: 1, wantRejected: false},
	}
	v := startDevVault(t)
	v.mustWrite(t, "sys/mounts/root", map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}})
	v.mustWrite(t, "root/root/generate/internal", map[string]any{
		"common_name": "pathlen root", "key_type": "ec", "key_bits": 384, "ttl": "87600h",
	})

	index := 0
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			index++
			issuer := "issuer-" + strconv.Itoa(index)
			signed := v.mustWrite(t, "root/root/sign-intermediate", map[string]any{
				"csr": v.mountIntermediate(t, issuer), "common_name": issuer, "max_path_length": tc.maxPathLength, "ttl": "8760h",
			})
			v.mustWrite(t, issuer+"/intermediate/set-signed", map[string]any{"certificate": signed["certificate"]})

			subordinate := "subordinate-" + strconv.Itoa(index)
			_, err := v.write(t, issuer+"/root/sign-intermediate", map[string]any{
				"csr": v.mountIntermediate(t, subordinate), "common_name": subordinate, "ttl": "720h",
			})
			if tc.wantRejected && err == nil {
				t.Fatalf("an issuer with max_path_length %d signed a subordinate CA", tc.maxPathLength)
			}
			if !tc.wantRejected && err != nil {
				t.Fatalf("an issuer with max_path_length %d refused a subordinate CA: %v", tc.maxPathLength, err)
			}
			if err != nil {
				t.Logf("Vault rejection: %v", err)
			}
		})
	}
}
