package backend

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) frontend(c *gin.Context) {
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/idp/") {
		c.JSON(http.StatusNotFound, gin.H{"detail": "not found"})
		return
	}
	dist := s.cfg.FrontendDistDir
	target := filepath.Join(dist, filepath.Clean(path))
	if path == "/" || !fileExists(target) {
		target = filepath.Join(dist, "index.html")
	}
	if !fileExists(target) {
		c.JSON(http.StatusNotFound, gin.H{"detail": "frontend dist not found"})
		return
	}
	c.File(target)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
