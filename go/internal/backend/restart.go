package backend

import (
	"log"
	"os"
	"os/exec"
	"time"
)

var packageControlScripts = []string{
	"/var/packages/DSMPASS/scripts/start-stop-status",
}

func (s *Server) schedulePackageRestart(reason string) {
	script := ""
	for _, candidate := range packageControlScripts {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			script = candidate
			break
		}
	}
	if script == "" {
		log.Printf("restart requested (%s), but no DSM package control script was found", reason)
		return
	}
	log.Printf("scheduling DSM package restart: %s", reason)
	go func() {
		time.Sleep(1200 * time.Millisecond)
		cmd := exec.Command("/bin/sh", script, "restart")
		if err := cmd.Start(); err != nil {
			log.Printf("failed to start DSM package restart: %v", err)
		}
	}()
}
