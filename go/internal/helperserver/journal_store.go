package helperserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

type accountJournalIndex struct {
	Username string   `json:"username"`
	Requests []string `json:"requests"`
}

func journalIndexPath(cfg config.HelperConfig, username string) string {
	return filepath.Join(cfg.JournalDir, "active-index", lineHash(strings.ToLower(username))+".json")
}

func readJournalIndex(path string) (accountJournalIndex, error) {
	var index accountJournalIndex
	data, err := os.ReadFile(path)
	if err != nil {
		return index, err
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return index, err
	}
	if index.Username == "" || len(index.Requests) == 0 {
		return index, errors.New("invalid account journal index")
	}
	for _, id := range index.Requests {
		if id == "" || safeName(id) != id {
			return index, errors.New("invalid indexed request ID")
		}
	}
	return index, nil
}

func updateJournalIndex(cfg config.HelperConfig, j journal, remove bool) error {
	path := journalIndexPath(cfg, j.DSMUsername)
	return withFileLock(path+".lock", func() error {
		index, err := readJournalIndex(path)
		if os.IsNotExist(err) {
			index = accountJournalIndex{Username: j.DSMUsername}
		} else if err != nil {
			return err
		}
		if !strings.EqualFold(index.Username, j.DSMUsername) {
			return errors.New("account journal index identity mismatch")
		}
		found := false
		ids := make([]string, 0, len(index.Requests)+1)
		for _, id := range index.Requests {
			if id == j.RequestID {
				found = true
				if remove {
					continue
				}
			}
			ids = append(ids, id)
		}
		if !found && !remove {
			ids = append(ids, j.RequestID)
		}
		if len(ids) == 0 {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return syncDirectory(filepath.Dir(path))
		}
		index.Requests = ids
		data, err := json.Marshal(index)
		if err != nil {
			return err
		}
		return writeFileAtomically(path, data, 0600)
	})
}

func terminalJournal(status string) bool {
	return status == "restored" || status == journalStatusSuperseded
}

func archiveJournal(cfg config.HelperConfig, requestID string) error {
	dir := filepath.Join(cfg.JournalDir, "completed")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(cfg.JournalDir, requestID+".json"), filepath.Join(dir, requestID+".json")); err != nil {
		return err
	}
	return errors.Join(syncDirectory(dir), syncDirectory(cfg.JournalDir))
}

// Old flat journals are indexed once before new writes. An unreadable legacy
// file with no account index cannot safely be assigned to a user; retain it and
// require repair instead of guessing which original password it might contain.
func ensureJournalStore(cfg config.HelperConfig) error {
	if cfg.JournalDir == "" {
		return errors.New("recovery journal directory is not configured")
	}
	marker := filepath.Join(cfg.JournalDir, "layout-v1")
	if _, err := os.Stat(marker); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return withFileLock(filepath.Join(cfg.JournalDir, "layout.lock"), func() error {
		if _, err := os.Stat(marker); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(filepath.Join(cfg.JournalDir, "active-index"), 0700); err != nil {
			return err
		}
		entries, err := os.ReadDir(cfg.JournalDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(cfg.JournalDir, entry.Name()))
			if err != nil {
				return err
			}
			var j journal
			if err := json.Unmarshal(data, &j); err != nil || j.RequestID == "" || j.DSMUsername == "" || entry.Name() != safeName(j.RequestID)+".json" {
				return fmt.Errorf("legacy recovery journal %s has no trustworthy account identity; repair it before migration", entry.Name())
			}
			if terminalJournal(j.Status) {
				if err := archiveJournal(cfg, j.RequestID); err != nil {
					return err
				}
			} else if err := updateJournalIndex(cfg, j, false); err != nil {
				return err
			}
		}
		return writeFileAtomically(marker, []byte("1\n"), 0600)
	})
}

// Only completed records expire. Active/unresolved recovery material and
// permanent password-reset request history are never pruned here.
func pruneCompletedJournals(cfg config.HelperConfig, now time.Time) error {
	marker := filepath.Join(cfg.JournalDir, "completed-cleanup")
	if info, err := os.Stat(marker); err == nil && now.Sub(info.ModTime()) < time.Hour {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Join(cfg.JournalDir, "completed")
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if info.Mode().IsRegular() && now.Sub(info.ModTime()) > 7*24*time.Hour {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !os.IsNotExist(err) {
				failures = append(failures, err)
			}
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return writeFileAtomically(marker, []byte(now.UTC().Format(time.RFC3339Nano)), 0600)
}
