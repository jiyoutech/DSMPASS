package main

import (
	"context"
	"log"

	"github.com/dsmpass/dsmpass/go/internal/backend"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperserver"
)

func main() {
	cfg := config.LoadHelper()
	if cfg.HMACSecret == "" {
		log.Fatal("DSMPASS_HELPER_HMAC_SECRET is required")
	}
	database, queries, err := backend.OpenDatabaseReader(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()
	server := helperserver.NewWithStore(cfg, queries)
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
