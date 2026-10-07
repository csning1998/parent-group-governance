package stateaudit

import (
	"encoding/base64"
	"slices"
	"testing"
)

// fakePrivateKey is a PEM private key block whose body carries no real key material.
var fakePrivateKey = "-----BEGIN " + "PRIVATE KEY-----\n" +
	"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
	"MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
	"-----END " + "PRIVATE KEY-----\n"

func TestGitleaksDetector(t *testing.T) {
	detector, err := NewGitleaksDetector()
	if err != nil || detector == nil {
		t.Fatalf("NewGitleaksDetector = %v, %v, want a detector", detector, err)
	}
	cases := []struct {
		name  string
		key   string
		value string
		want  Detection
	}{
		{"personal access token", "password", fakePAT, "gitleaks:gitlab-pat"},
		{"runner token", "token", fakeRunner, "gitleaks:gitlab-runner-authentication-token"},
		{"private key", "private_key", fakePrivateKey, "gitleaks:private-key"},
		{"base64 private key", "content_b64", base64.StdEncoding.EncodeToString([]byte(fakePrivateKey)), "gitleaks:private-key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detector.Detect(c.key, c.value)
			if !slices.Contains(got, c.want) {
				t.Errorf("Detect(%s) = %v, want %s", c.key, got, c.want)
			}
		})
	}
}

func TestGitleaksDetectorPassesPublicValues(t *testing.T) {
	detector, err := NewGitleaksDetector()
	if err != nil || detector == nil {
		t.Fatalf("NewGitleaksDetector = %v, %v, want a detector", detector, err)
	}
	for key, value := range map[string]string{
		"url":         "http://sonarqube:9000",
		"address":     "https://gitlab.com/api/v4/projects/86417732/terraform/state/group-topology",
		"name":        "platform-cluster-issuer",
		"mount_path":  "gitlab-saas-ci-job-jwt-provider",
		"description": "Routed libvirt guests reach DHCP, DNS, and the Bastion Vault listener of the host.",
	} {
		got := detector.Detect(key, value)
		if len(got) != 0 {
			t.Errorf("Detect(%s) = %v, want none", key, got)
		}
	}
}
