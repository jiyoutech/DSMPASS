package helperserver

import (
	"context"
	"log"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

const helperInitializingMessage = "Helper 正在迁移恢复日志并恢复密码，登录和同步暂不可用；请稍后刷新，无需反复重启。"

func (s *Server) setStartupState(starting bool, err error) {
	s.startupMu.Lock()
	defer s.startupMu.Unlock()
	s.starting = starting
	s.startupErr = errorString(err)
}

func (s *Server) startupStatus() (ready bool, startupError string) {
	s.startupMu.RLock()
	defer s.startupMu.RUnlock()
	return !s.starting, s.startupErr
}

// Serve authenticated health checks before disk-intensive migration. Existing
// controllers have a ten-second liveness deadline and do not know startup_ready.
// All other RPCs stay closed until migration and the initial recovery pass end.
func (s *Server) initializeRecovery(ctx context.Context, cfg config.HelperConfig) {
	for ctx.Err() == nil {
		if err := ensureJournalStore(cfg); err != nil {
			s.setStartupState(true, err)
			log.Printf("DSM Pass helper journal migration pending: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err := recoverPending(cfg); err != nil {
			// Once every legacy record has an account index, unresolved accounts
			// are blocked by their own journal guards; other users can proceed.
			log.Printf("DSM Pass helper password recovery incomplete: %v", err)
		}
		if ctx.Err() != nil {
			return
		}
		s.setStartupState(false, nil)
		runRecoveryLoop(ctx, cfg)
		return
	}
}
