package backend

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func writeItems(c *gin.Context, rows []map[string]any, err error) {
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows})
}

func check(name string, passed bool, detail string, warning bool) gin.H {
	status := "pass"
	if !passed && warning {
		status = "warning"
	} else if !passed {
		status = "fail"
	}
	return gin.H{"name": name, "status": status, "detail": detail}
}
