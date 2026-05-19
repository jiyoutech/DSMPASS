package backend

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/gin-gonic/gin"
)

var packageControlScripts = []string{
	"/var/packages/DSMPASS/scripts/start-stop-status",
}

func (s *Server) schedulePackageRestart(reason string) error {
	script := ""
	for _, candidate := range packageControlScripts {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			script = candidate
			break
		}
	}
	if script == "" {
		log.Printf("restart requested (%s), but no DSM package control script was found", reason)
		return fmt.Errorf("DSM package control script was not found")
	}
	log.Printf("scheduling DSM package restart: %s", reason)
	go func() {
		time.Sleep(1200 * time.Millisecond)
		cmd := exec.Command("/bin/sh", script, "restart")
		if err := cmd.Start(); err != nil {
			log.Printf("failed to start DSM package restart: %v", err)
		}
	}()
	return nil
}

func (s *Server) restartPackageHandler(c *gin.Context) {
	if err := s.schedulePackageRestart("manual management restart"); err != nil {
		writeError(c, internalError(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}
