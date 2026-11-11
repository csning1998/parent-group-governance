// Package pkipathlen verifies Path Length Constraint enforcement across Vault PKI intermediate certificate authorities.
package pkipathlen

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	rootToken   = "pathlen-test"
	rootCAMount = "root-ca"
)

// devVault provides an isolated, ephemeral Vault development server instance for integration verification.
type devVault struct {
	address string
	client  *http.Client
	mounts  int
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

// mountRootCA enables a PKI secrets engine at root-ca and generates a self-signed root CA without a Path Length Constraint.
func (v *devVault) mountRootCA(t *testing.T) {
	t.Helper()
	v.mustWrite(t, "sys/mounts/"+rootCAMount, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}})
	v.mustWrite(t, rootCAMount+"/root/generate/internal", map[string]any{
		"common_name": "pathlen root", "key_type": "ec", "key_bits": 384, "ttl": "87600h",
	})
}

// signIntermediate signs the CSR of a new PKI mount through the issuer mount and imports the signed certificate into the new mount.
func (v *devVault) signIntermediate(t *testing.T, issuer string, params map[string]any) (string, *x509.Certificate, error) {
	t.Helper()
	v.mounts++
	mount := "ca-" + strconv.Itoa(v.mounts)
	body := map[string]any{"csr": v.mountIntermediate(t, mount), "common_name": mount}
	maps.Copy(body, params)
	data, err := v.write(t, issuer+"/root/sign-intermediate", body)
	if err != nil {
		return "", nil, err
	}
	certificate, _ := data["certificate"].(string)
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		t.Fatalf("%s returned no PEM certificate", issuer)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	v.mustWrite(t, mount+"/intermediate/set-signed", map[string]any{"certificate": certificate})
	return mount, cert, nil
}

// assertSignResult checks the Path Length Constraint of a signed CA certificate, or the reason of a rejection when wantError is set.
func assertSignResult(t *testing.T, cert *x509.Certificate, err error, wantPathLength int, wantError string) {
	t.Helper()
	switch {
	case wantError != "" && err == nil:
		t.Fatalf("the issuer signed a subordinate CA with path length %d, want a rejection containing %q", cert.MaxPathLen, wantError)
	case wantError != "" && !strings.Contains(err.Error(), wantError):
		t.Fatalf("the issuer rejected a subordinate CA for another reason: %v", err)
	case wantError == "" && err != nil:
		t.Fatalf("the issuer rejected a subordinate CA: %v", err)
	case wantError == "" && (cert.MaxPathLen != wantPathLength || cert.MaxPathLenZero != (wantPathLength == 0)):
		t.Fatalf("the subordinate CA carries path length %d, want %d", cert.MaxPathLen, wantPathLength)
	}
}

func TestSignIntermediateEnforcesTheMaxPathLengthOfTheIssuer(t *testing.T) {
	cases := map[string]struct {
		issuerPathLength int
		request          map[string]any
		wantPathLength   int
		wantError        string
	}{
		"path length zero rejects a subordinate CA": {
			issuerPathLength: 0,
			wantError:        "signing certificate has a max path length of zero",
		},
		"path length zero rejects an explicit path length": {
			issuerPathLength: 0,
			request:          map[string]any{"max_path_length": 5},
			wantError:        "requested max_path_length 5 is not allowed",
		},
		"path length one derives path length zero for a subordinate CA": {
			issuerPathLength: 1,
			wantPathLength:   0,
		},
		"path length one admits an explicit path length zero": {
			issuerPathLength: 1,
			request:          map[string]any{"max_path_length": 0},
			wantPathLength:   0,
		},
		"path length one rejects an explicit equal path length": {
			issuerPathLength: 1,
			request:          map[string]any{"max_path_length": 1},
			wantError:        "requested max_path_length 1 is not allowed",
		},
		"path length one rejects an explicit unlimited path length": {
			issuerPathLength: 1,
			request:          map[string]any{"max_path_length": -1},
			wantError:        "requested max_path_length -1 is not allowed",
		},
	}
	v := startDevVault(t)
	v.mountRootCA(t)

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			issuer, _, err := v.signIntermediate(t, rootCAMount, map[string]any{"max_path_length": tc.issuerPathLength, "ttl": "8760h"})
			if err != nil {
				t.Fatal(err)
			}
			request := map[string]any{"ttl": "720h"}
			maps.Copy(request, tc.request)
			_, cert, err := v.signIntermediate(t, issuer, request)
			assertSignResult(t, cert, err, tc.wantPathLength, tc.wantError)
		})
	}
}

func TestSignIntermediateDecrementsThePathLengthAlongTheChain(t *testing.T) {
	v := startDevVault(t)
	v.mountRootCA(t)

	issuer := rootCAMount
	for _, step := range []struct {
		request        map[string]any
		wantPathLength int
	}{
		{request: map[string]any{"max_path_length": 2, "ttl": "8760h"}, wantPathLength: 2},
		{request: map[string]any{"ttl": "4380h"}, wantPathLength: 1},
		{request: map[string]any{"ttl": "2190h"}, wantPathLength: 0},
	} {
		mount, cert, err := v.signIntermediate(t, issuer, step.request)
		assertSignResult(t, cert, err, step.wantPathLength, "")
		issuer = mount
	}
	_, cert, err := v.signIntermediate(t, issuer, map[string]any{"ttl": "1095h"})
	assertSignResult(t, cert, err, 0, "signing certificate has a max path length of zero")
}
