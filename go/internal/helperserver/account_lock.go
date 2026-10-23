package helperserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

var errAccountBusy = errors.New("account operation is busy; retry after the current operation finishes")

// Lock files have a stable inode: never unlink them, including during recovery.
// Every writer takes the account lock before the project-wide writer lock.
func withFileLock(path string, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return withFileLockContext(ctx, path, fn)
}

func withFileLockContext(ctx context.Context, path string, fn func() error) error {
	file, err := openLockFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(errAccountBusy, err)
		}
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(errAccountBusy, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	locked, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(locked, current) {
		return fmt.Errorf("lock file was replaced: %s", path)
	}
	return fn()
}

func withShadowWrite(cfg config.HelperConfig, fn func() error) error {
	return withFileLock(cfg.ShadowLockPath, func() error {
		path, err := shadowSystemLockPath(cfg)
		if err != nil {
			return err
		}
		return withFileLock(path, fn)
	})
}

// Native account commands acquire DSM's lock themselves. Holding that lock in
// their parent would deadlock; retain only the two project locks here.
func withAccountMutation(cfg config.HelperConfig, username string, disable bool, fn func() error) error {
	return withFileLock(lockPath(cfg.LockDir, username), func() error {
		j, found, err := browserLeaseForUser(cfg, username)
		if err != nil {
			return err
		}
		var restoreErr error
		if found {
			if !disable {
				return errBrowserLoginInProgress
			}
			// Revoke the temporary credential before disabling. If recovery fails,
			// still apply the disable; subsequent recovery preserves its flags.
			restoreErr = restoreJournalUnderAccountLock(cfg, j, "account_disabled")
			if restoreErr != nil {
				restoreErr = errors.Join(restoreErr, recordRecoveryFailure(cfg, j.RequestID))
			}
		}
		return errors.Join(restoreErr, withFileLock(cfg.ShadowLockPath, fn))
	})
}
