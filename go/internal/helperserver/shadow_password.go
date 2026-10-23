package helperserver

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// temporaryShadowLine changes only the password field. Account expiration,
// password aging and the original record remain intact for conditional recovery.
func temporaryShadowLine(opensslPath, username, original, password string) (string, error) {
	fields := strings.Split(original, ":")
	if username == "" || strings.ContainsAny(username, ":\r\n\x00") ||
		len(fields) != 9 || fields[0] != username || strings.ContainsAny(original, "\r\n\x00") {
		return "", errors.New("invalid DSM shadow record")
	}
	if fields[1] == "" || strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*") {
		return "", errors.New("refusing temporary login for a locked or passwordless DSM account")
	}
	if password == "" || len(password) > 127 || strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("invalid temporary DSM password")
	}
	if opensslPath == "" {
		opensslPath = "/usr/bin/openssl"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, opensslPath, "passwd", "-6", "-stdin")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "OPENSSL_CONF=/dev/null"}
	command.Stdin = strings.NewReader(password + "\n")
	output, err := command.Output()
	if err != nil {
		// Do not include subprocess output: it may contain password material.
		return "", fmt.Errorf("generate temporary shadow password hash: %w", err)
	}
	hash := strings.TrimSpace(string(output))
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "6" ||
		len(parts[2]) == 0 || len(parts[2]) > 16 || len(parts[3]) != 86 ||
		!isCryptBase64(parts[2]) || !isCryptBase64(parts[3]) {
		return "", errors.New("invalid SHA-512 crypt output from openssl")
	}
	fields[1] = hash
	return strings.Join(fields, ":"), nil
}

func isCryptBase64(value string) bool {
	for _, c := range value {
		if !strings.ContainsRune("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", c) {
			return false
		}
	}
	return true
}
