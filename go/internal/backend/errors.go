package backend

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type appError struct {
	status int
	detail string
	err    error
}

func (e appError) Error() string {
	if e.detail != "" {
		return e.detail
	}
	if e.err != nil {
		return e.err.Error()
	}
	return http.StatusText(e.status)
}

func badRequest(detail string) appError {
	return appError{status: http.StatusBadRequest, detail: detail}
}

func internalError(err error) appError {
	return appError{status: http.StatusInternalServerError, err: err}
}

func writeError(c *gin.Context, err error) {
	if typed, ok := err.(appError); ok {
		c.JSON(typed.status, gin.H{"detail": typed.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
}
