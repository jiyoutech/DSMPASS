package main

import (
	"context"
	"log"
	"os"

	"github.com/dsmpass/dsmpass/go/internal/backend"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperserver"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "install-helper" {
		if err := helperserver.InstallPrivilegedHelper(); err != nil {
			log.Fatal(err)
		}
		log.Print("protected Helper and restricted sudo rule installed")
		return
	}
	cfg, err := config.LoadPrivilegedHelper()
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 3 && os.Args[1] == "control" {
		if err := helperserver.ControlPrivilegedHelper(cfg, os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) != 1 {
		log.Fatal("unsupported Helper command")
	}
	if err := helperserver.PreparePrivilegedRuntime(cfg); err != nil {
		log.Fatal(err)
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
