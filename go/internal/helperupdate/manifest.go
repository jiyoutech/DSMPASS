package helperupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Only this public key is installed on a NAS. The release seed stays with the
// publisher; package files and backend configuration cannot replace the key.
const PublicKey = "Hbt0HrX7UbZdqwjj1Zs5r0qHf+ubfCj7ScrefewEKHo="
const Domain = "DSMPASS protected Helper release v1\n"
const ManifestFile = "helper-release.json"
const SignatureFile = "helper-release.sig"

type Manifest struct {
	Format     int    `json:"format"`
	Version    string `json:"version"`
	Revision   string `json:"revision"`
	BuildEpoch int64  `json:"build_epoch"`
	Arch       string `json:"arch"`
	Helper     string `json:"helper_sha256"`
	Controller string `json:"controller_sha256"`
}

type Payload struct {
	Manifest   Manifest
	Binary     []byte
	Controller []byte
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Read regular files with bounded size, without blocking on attacker-supplied
// FIFOs. Verification and installation use the same captured bytes.
func ReadFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("invalid release file: %s", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("cannot read bounded release file: %s", filepath.Base(path))
	}
	return data, nil
}

func Load(dir, arch string, currentEpoch int64) (Payload, error) {
	var payload Payload
	manifest, err := ReadFile(filepath.Join(dir, ManifestFile), 8192)
	if err != nil {
		return payload, fmt.Errorf("signed Helper manifest unavailable: %w", err)
	}
	signature, err := ReadFile(filepath.Join(dir, SignatureFile), 256)
	if err != nil {
		return payload, err
	}
	key, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil {
		return payload, err
	}
	payload.Manifest, err = verifyManifest(manifest, signature, key, arch, currentEpoch)
	if err != nil {
		return payload, err
	}
	payload.Binary, err = ReadFile(filepath.Join(dir, "bin/dsmpass-helper"), 100<<20)
	if err != nil {
		return payload, err
	}
	payload.Controller, err = ReadFile(filepath.Join(dir, "helper-control.sh"), 64<<10)
	if err != nil {
		return payload, err
	}
	if err := payload.VerifyHashes(); err != nil {
		return Payload{}, err
	}
	return payload, nil
}

func verifyManifest(data, signature, key []byte, arch string, currentEpoch int64) (Manifest, error) {
	var manifest Manifest
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(Domain), data...), sig) {
		return manifest, errors.New("Helper release signature is invalid; protected files were not changed")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return manifest, errors.New("Helper manifest contains trailing data")
	}
	if manifest.Format != 1 || manifest.Version == "" || manifest.Revision == "" || manifest.BuildEpoch <= 0 || manifest.Arch != arch {
		return manifest, errors.New("Helper release metadata or architecture is incompatible")
	}
	if manifest.BuildEpoch < currentEpoch {
		return manifest, errors.New("Helper downgrade requires explicit root installation")
	}
	for _, hash := range []string{manifest.Helper, manifest.Controller} {
		if len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" {
			return manifest, errors.New("invalid Helper release checksum")
		}
	}
	return manifest, nil
}

func (p Payload) VerifyHashes() error {
	if Digest(p.Binary) != p.Manifest.Helper || Digest(p.Controller) != p.Manifest.Controller {
		return errors.New("Helper release checksum mismatch; protected files were not changed")
	}
	return nil
}
