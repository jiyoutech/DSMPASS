package backend

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var helperControlScripts = []string{
	"/var/packages/DSMPASS/target/helper-control.sh",
}

func (s *Server) restartHelper(c *gin.Context) {
	if err := s.restartHelperProcess(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) restartHelperProcess(ctx context.Context) error {
	script := ""
	for _, candidate := range helperControlScripts {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			script = candidate
			break
		}
	}
	if script == "" {
		return fmt.Errorf("helper-control.sh not found; reinstall the latest SPK or restart Helper over SSH")
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, script, "restart")
	output, err := cmd.CombinedOutput()
	if cmdCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("helper restart timed out")
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return fmt.Errorf("helper restart failed: %w", err)
		}
		return fmt.Errorf("helper restart failed: %w: %s", err, detail)
	}
	return nil
}
