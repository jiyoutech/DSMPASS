package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigningKeyValidation(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key.Seed())
	publicKey := base64.StdEncoding.EncodeToString(pub)
	for _, tc := range []struct {
		name, value, wantError string
	}{
		{"valid", encoded, ""},
		{"whitespace", "\n " + encoded + "\n", ""},
		{"missing", "", "base64 Ed25519 seed"},
		{"invalid", "not base64", "base64 Ed25519 seed"},
		{"short", base64.StdEncoding.EncodeToString([]byte("short")), "base64 Ed25519 seed"},
		{"wrong key", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)), "pinned public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DSMPASS_HELPER_SIGNING_KEY_FILE", "")
			t.Setenv("DSMPASS_HELPER_SIGNING_KEY", tc.value)
			got, err := signingKey(publicKey)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("expected %q, got %v", tc.wantError, err)
				}
			} else if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("valid signing key rejected: %v", err)
			}
		})
	}
	t.Run("file overrides environment and must exist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "seed")
		if err := os.WriteFile(path, []byte(encoded+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DSMPASS_HELPER_SIGNING_KEY_FILE", path)
		t.Setenv("DSMPASS_HELPER_SIGNING_KEY", "invalid")
		got, err := signingKey(publicKey)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("valid key file rejected: %v", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := signingKey(publicKey); !os.IsNotExist(err) {
			t.Fatalf("missing key file did not fail: %v", err)
		}
	})
}

func TestSignRefusesMissingOrWrongKeyBeforeWriting(t *testing.T) {
	t.Setenv("DSMPASS_HELPER_SIGNING_KEY_FILE", "")
	for _, value := range []string{"", "malformed", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))} {
		t.Setenv("DSMPASS_HELPER_SIGNING_KEY", value)
		dir := t.TempDir()
		if err := sign(dir, "1.0.0", "revision", "amd64", 1); err == nil {
			t.Fatal("invalid signing configuration accepted")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("invalid signer wrote release files: %v", err)
		}
	}
}
