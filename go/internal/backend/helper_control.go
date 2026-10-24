package backend

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
	"github.com/gin-gonic/gin"
)

var helperControlScripts = []string{
	config.HelperControlPath,
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

	cmdCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := runHelperControl(cmdCtx, script, "restart"); err != nil {
		return err
	}
	if buildinfo.Version != "dev" {
		health, err := s.helper.HealthCheck(cmdCtx)
		if err != nil {
			return err
		}
		if helperclient.CheckCompatibility(health, buildinfo.Version, buildinfo.Revision) != nil {
			if err := runHelperControl(cmdCtx, script, "upgrade"); err != nil {
				return fmt.Errorf("Helper 自动更新未完成；首次迁移或未签名套件需管理员执行 setup-helper-sudo.sh 一次: %w", err)
			}
			health, err = s.helper.HealthCheck(cmdCtx)
			if err != nil {
				return err
			}
			return helperclient.CheckCompatibility(health, buildinfo.Version, buildinfo.Revision)
		}
	}
	return nil
}

func runHelperControl(cmdCtx context.Context, script, action string) error {
	cmd := exec.CommandContext(cmdCtx, script, action)
	output, err := cmd.CombinedOutput()
	if cmdCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("Helper %s timed out", action)
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return fmt.Errorf("Helper %s failed: %w", action, err)
		}
		return fmt.Errorf("Helper %s failed: %w: %s", action, err, detail)
	}
	return nil
}
