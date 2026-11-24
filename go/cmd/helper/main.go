package main

import (
	"errors"
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
	if len(os.Args) >= 2 && os.Args[1] == "install-helper" {
		review, err := installGroupReview(os.Args[2:])
		if err != nil {
			log.Fatal(err)
		}
		if err := helperserver.InstallPrivilegedHelper(review); err != nil {
			log.Fatal(err)
		}
		log.Print("protected Helper and restricted sudo rule installed")
		return
	}
	cfg, err := config.LoadPrivilegedHelper()
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) >= 2 && os.Args[1] == "bind-dingtalk-logins" {
		dryRun := len(os.Args) == 4 && os.Args[3] == "--dry-run"
		if len(os.Args) != 3 && !dryRun {
			log.Fatal("usage: bind-dingtalk-logins SOURCE [--dry-run]")
		}
		total, err := helperserver.BindDingTalkLogins(cfg, os.Args[2], dryRun)
		if err != nil {
			log.Fatal(err)
		}
		if dryRun {
			log.Printf("可建立登录及全量改密归属 %d 个", total)
		} else {
			log.Printf("本次新增登录及全量改密归属 %d 个", total)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "finalize-upgrade" {
		if err := helperserver.FinalizePrivilegedUpgrade(cfg); err != nil {
			log.Fatal(err)
		}
		return
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

func installGroupReview(args []string) (helperserver.LegacyGroupReview, error) {
	switch {
	case len(args) == 0, len(args) == 1 && args[0] == "--reuse-local-groups":
		return func(groups map[string]int) (map[string]int, error) { return groups, nil }, nil
	case len(args) == 1 && args[0] == "--review-local-groups":
		return func(groups map[string]int) (map[string]int, error) {
			return reviewLocalGroups(os.Stdin, os.Stdout, groups)
		}, nil
	default:
		return nil, errors.New("usage: install-helper [--reuse-local-groups | --review-local-groups]")
	}
}
