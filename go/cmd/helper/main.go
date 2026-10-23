package main

import (
	"log"
	"os"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperserver"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "query-account" {
		if err := queryAccount(); err != nil {
			log.Fatal(err)
		}
		return
	}
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
	if len(os.Args) == 3 && (os.Args[1] == "authorize-user" || os.Args[1] == "revoke-user" || os.Args[1] == "authorize-group" || os.Args[1] == "revoke-group") {
		if err := helperserver.ManageAccountPolicy(cfg, os.Args[1], os.Args[2]); err != nil {
			log.Fatal(err)
		}
		return
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
	server := helperserver.New(cfg)
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}
