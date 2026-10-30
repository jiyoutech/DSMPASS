// sign-helper runs on the publishing machine, never on a NAS.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/helperupdate"
)

func main() {
	dir := flag.String("dir", "", "package directory")
	version := flag.String("version", "", "release version")
	revision := flag.String("revision", "", "source revision")
	arch := flag.String("arch", "", "Go architecture")
	epoch := flag.Int64("epoch", 0, "build timestamp")
	checkKey := flag.Bool("check-key", false, "validate the signing key without building a release")
	flag.Parse()
	if *checkKey {
		if _, err := signingKey(helperupdate.PublicKey); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := sign(*dir, *version, *revision, *arch, *epoch); err != nil {
		log.Fatal(err)
	}
}

func signingKey(publicKey string) (ed25519.PrivateKey, error) {
	seedText := os.Getenv("DSMPASS_HELPER_SIGNING_KEY")
	if path := os.Getenv("DSMPASS_HELPER_SIGNING_KEY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		seedText = string(data)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedText))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("release signing requires a base64 Ed25519 seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) != publicKey {
		return nil, errors.New("release signing key does not match the pinned public key")
	}
	return key, nil
}

func sign(dir, version, revision, arch string, epoch int64) error {
	key, err := signingKey(helperupdate.PublicKey)
	if err != nil {
		return err
	}
	if dir == "" || version == "" || revision == "" || epoch <= 0 || (arch != "amd64" && arch != "arm64") {
		return errors.New("incomplete release metadata")
	}
	binary, err := helperupdate.ReadFile(filepath.Join(dir, "bin/dsmpass-helper"), 100<<20)
	if err != nil {
		return err
	}
	controller, err := helperupdate.ReadFile(filepath.Join(dir, "helper-control.sh"), 64<<10)
	if err != nil {
		return err
	}
	manifest, err := json.Marshal(helperupdate.Manifest{Format: 1, Version: version, Revision: revision,
		Arch: arch, BuildEpoch: epoch, Helper: helperupdate.Digest(binary), Controller: helperupdate.Digest(controller)})
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, append([]byte(helperupdate.Domain), manifest...))
	if err := os.WriteFile(filepath.Join(dir, helperupdate.ManifestFile), manifest, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, helperupdate.SignatureFile), []byte(base64.StdEncoding.EncodeToString(signature)+"\n"), 0644)
}
