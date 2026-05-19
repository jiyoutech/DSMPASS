package backend

import (
	"context"
	"errors"
	"log"
	"time"
)

func (s *Server) StartSyncScheduler(ctx context.Context) {
	go s.syncScheduler(ctx)
}

func (s *Server) syncScheduler(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	s.runDueScheduledSyncs(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueScheduledSyncs(ctx)
		}
	}
}

func (s *Server) runDueScheduledSyncs(ctx context.Context) {
	rows, err := s.store.DBTX().QueryContext(ctx, `
SELECT slug, config_json
FROM identity_sources
WHERE enabled = 1 AND directory_sync_enabled = 1
`)
	if err != nil {
		log.Printf("scheduled sync query failed: %v", err)
		return
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var slug, rawConfig string
		if err := rows.Scan(&slug, &rawConfig); err != nil {
			log.Printf("scheduled sync scan failed: %v", err)
			continue
		}
		sourceConfig := decodeSourceConfig(rawConfig)
		if sourceConfig.SyncIntervalMinutes <= 0 {
			continue
		}
		interval := time.Duration(sourceConfig.SyncIntervalMinutes) * time.Minute
		s.syncMu.Lock()
		last := s.autoSync[slug]
		if !last.IsZero() && now.Sub(last) < interval {
			s.syncMu.Unlock()
			continue
		}
		s.autoSync[slug] = now
		s.syncMu.Unlock()
		go func(sourceSlug string) {
			if _, err := s.runSyncProvider(context.Background(), sourceSlug); err != nil {
				if errors.Is(err, errSyncAlreadyRunning) {
					return
				}
				log.Printf("scheduled sync failed source=%s error=%v", sourceSlug, err)
			} else {
				log.Printf("scheduled sync completed source=%s", sourceSlug)
			}
		}(slug)
	}
	if err := rows.Err(); err != nil {
		log.Printf("scheduled sync rows failed: %v", err)
	}
}
