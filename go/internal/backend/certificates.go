package backend

import (
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func (s *Server) uploadCertificate(c *gin.Context) {
	scope := c.Param("scope")
	certFile, keyFile, restartRequired, ok := s.certificateTarget(scope)
	if !ok {
		writeError(c, badRequest("invalid certificate scope"))
		return
	}
	certHeader, err := c.FormFile("cert")
	if err != nil {
		writeError(c, badRequest("missing cert file"))
		return
	}
	keyHeader, err := c.FormFile("key")
	if err != nil {
		writeError(c, badRequest("missing key file"))
		return
	}
	certData, err := readUploadedFile(certHeader)
	if err != nil {
		writeError(c, internalError(err))
		return
	}
	keyData, err := readUploadedFile(keyHeader)
	if err != nil {
		writeError(c, internalError(err))
		return
	}
	if _, err := tls.X509KeyPair(certData, keyData); err != nil {
		writeError(c, badRequest("certificate and private key do not match"))
		return
	}
	if err := writeCertificatePair(certFile, keyFile, certData, keyData); err != nil {
		writeError(c, internalError(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success":          true,
		"scope":            scope,
		"restart_required": restartRequired,
	})
}

func (s *Server) certificateTarget(scope string) (string, string, bool, bool) {
	switch scope {
	case "admin":
		return s.cfg.TLSCertFile, s.cfg.TLSKeyFile, true, true
	case "idp":
		return s.cfg.IDPTLSCertFile, s.cfg.IDPTLSKeyFile, false, true
	default:
		return "", "", false, false
	}
}

func readUploadedFile(header *multipart.FileHeader) ([]byte, error) {
	file, err := header.Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 2<<20))
}

func writeCertificatePair(certFile, keyFile string, certData, keyData []byte) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}
	certTemp := certFile + ".tmp"
	keyTemp := keyFile + ".tmp"
	if err := os.WriteFile(certTemp, certData, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyTemp, keyData, 0o600); err != nil {
		_ = os.Remove(certTemp)
		return err
	}
	if err := os.Rename(certTemp, certFile); err != nil {
		_ = os.Remove(certTemp)
		_ = os.Remove(keyTemp)
		return err
	}
	if err := os.Rename(keyTemp, keyFile); err != nil {
		_ = os.Remove(keyTemp)
		return err
	}
	return nil
}

func (s *Server) restartIDPRouteHandler(c *gin.Context) {
	if err := s.restartIDPRouteNow("manual idp route restart"); err != nil {
		writeError(c, internalError(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}
