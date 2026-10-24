package helperupdate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseManifestAuthenticationAndReplay(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := Manifest{Format: 1, Version: "0.8.49", Revision: "revision-a", BuildEpoch: 200, Arch: "amd64", Helper: Digest([]byte("binary")), Controller: Digest([]byte("controller"))}
	for _, tc := range []struct {
		name    string
		edit    func(*Manifest)
		arch    string
		epoch   int64
		invalid bool
	}{
		{"valid", nil, "amd64", 100, false},
		{"equal-epoch", nil, "amd64", 200, false},
		{"downgrade", nil, "amd64", 201, true},
		{"wrong-architecture", nil, "arm64", 100, true},
		{"missing-version", func(m *Manifest) { m.Version = "" }, "amd64", 100, true},
		{"missing-revision", func(m *Manifest) { m.Revision = "" }, "amd64", 100, true},
		{"zero-epoch", func(m *Manifest) { m.BuildEpoch = 0 }, "amd64", 0, true},
		{"future-format", func(m *Manifest) { m.Format = 2 }, "amd64", 100, true},
		{"bad-checksum", func(m *Manifest) { m.Helper = "short" }, "amd64", 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			if tc.edit != nil {
				tc.edit(&m)
			}
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(Domain), data...))))
			_, err = verifyManifest(data, sig, public, tc.arch, tc.epoch)
			if (err != nil) != tc.invalid {
				t.Fatalf("unexpected verification: %v", err)
			}
		})
	}
	data, _ := json.Marshal(base)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(Domain), data...))))
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		data, sig, key []byte
	}{
		{"tampered", append(append([]byte{}, data...), ' '), sig, public},
		{"unsigned", data, nil, public},
		{"bad-signature", data, []byte("invalid"), public},
		{"wrong-key", data, sig, other},
		{"empty-key", data, sig, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyManifest(tc.data, tc.sig, tc.key, "amd64", 100); err == nil {
				t.Fatal("accepted unauthenticated release")
			}
		})
	}
	for _, invalid := range [][]byte{[]byte(`{}`), append(append([]byte{}, data...), []byte(` {}`)...), []byte(`{"unknown":true}`)} {
		signed := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(Domain), invalid...))))
		if _, err := verifyManifest(invalid, signed, public, "amd64", 100); err == nil {
			t.Fatal("accepted invalid signed metadata")
		}
	}
}

func TestPayloadIntegrity(t *testing.T) {
	p := Payload{Binary: []byte("binary"), Controller: []byte("controller")}
	p.Manifest.Helper = Digest(p.Binary)
	p.Manifest.Controller = Digest(p.Controller)
	if err := p.VerifyHashes(); err != nil {
		t.Fatal(err)
	}
	p.Binary[0] = 'x'
	if err := p.VerifyHashes(); err == nil {
		t.Fatal("accepted tampered binary")
	}
	p.Binary = []byte("binary")
	p.Controller[0] = 'x'
	if err := p.VerifyHashes(); err == nil {
		t.Fatal("accepted tampered controller")
	}
}

func TestReleaseFileBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload")
	if err := os.WriteFile(path, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(path, 5); err != nil || string(data) != "12345" {
		t.Fatalf("read: %q %v", data, err)
	}
	if _, err := ReadFile(path, 4); err == nil {
		t.Fatal("accepted oversized payload")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir, filepath.Join(dir, "missing")} {
		if _, err := ReadFile(path, 10); err == nil {
			t.Fatal("accepted non-regular release file")
		}
	}
	if _, err := Load(dir, "amd64", 0); err == nil {
		t.Fatal("accepted unsigned release directory")
	}
}
