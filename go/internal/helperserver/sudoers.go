package helperserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

func installHelperSudoers() error {
	rule := []byte(helperSudoersRule())
	for _, visudo := range []string{"/usr/sbin/visudo", "/usr/bin/visudo"} {
		if _, err := os.Stat(visudo); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(helperSudoersPath), ".DSMPASS-helper-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(rule); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := runSudoRuleValidator(visudo, "-cf", tmp.Name()); err != nil {
			return err
		}
		return securefs.WriteRootFile(helperSudoersPath, rule, 0440)
	}
	// DSM may ship sudo without visudo. The rule is a fixed, tested template:
	// atomically install it, ask sudo's real policy parser to check an allowed
	// command without executing it, and restore the prior rule on any failure.
	if err := securefs.CheckRootPath(filepath.Dir(helperSudoersPath)); err != nil {
		return err
	}
	if _, err := os.Lstat(helperSudoersPath); err == nil {
		if err := securefs.CheckRootPath(helperSudoersPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return replaceVerifiedSudoers(helperSudoersPath, rule, func(data []byte) error {
		return securefs.WriteRootFile(helperSudoersPath, data, 0440)
	}, func() error {
		return runSudoRuleValidator("/usr/bin/sudo", "-n", "-l", "-U", "DSMPASS", "--", config.HelperControlPath, "status")
	})
}

func runSudoRuleValidator(path string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil || stderr.Len() != 0 {
		return fmt.Errorf("validate Helper sudo rule: %v: %s", err, stderr.String())
	}
	return nil
}

func replaceVerifiedSudoers(path string, rule []byte, write func([]byte) error, validate func() error) error {
	previous, err := os.ReadFile(path)
	missing := os.IsNotExist(err)
	if err != nil && !missing {
		return err
	}
	if err := write(rule); err != nil {
		return err
	}
	if err := validate(); err != nil {
		current, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(current, rule) {
			return errors.Join(err, errors.New("sudo rule changed during validation; refusing to overwrite concurrent changes"), readErr)
		}
		var rollbackErr error
		if missing {
			rollbackErr = os.Remove(path)
		} else {
			rollbackErr = write(previous)
		}
		return errors.Join(err, rollbackErr)
	}
	return nil
}
