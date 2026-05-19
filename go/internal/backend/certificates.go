package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		writeError(c, badRequest("certificate and private key do not match"))
		return
	}
	domains := certificateDomains(pair)
	appliedAccessHost := ""
	if err := writeCertificatePair(certFile, keyFile, certData, keyData); err != nil {
		writeError(c, internalError(err))
		return
	}
	if scope == "idp" {
		appliedAccessHost = preferredCertificateAccessHost(domains)
		if appliedAccessHost != "" {
			if err := s.applyCertificateAccessHost(c.Request.Context(), appliedAccessHost); err != nil {
				writeError(c, err)
				return
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success":             true,
		"scope":               scope,
		"restart_required":    restartRequired,
		"certificate_domains": domains,
		"applied_access_host": appliedAccessHost,
	})
}

func (s *Server) certificateTarget(scope string) (string, string, bool, bool) {
	switch scope {
	case "idp":
		return s.cfg.IDPTLSCertFile, s.cfg.IDPTLSKeyFile, false, true
	default:
		return "", "", false, false
	}
}

func certificateDomains(pair tls.Certificate) []string {
	seen := map[string]bool{}
	domains := []string{}
	for _, raw := range pair.Certificate {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		for _, name := range cert.DNSNames {
			addCertificateDomain(&domains, seen, name)
		}
		addCertificateDomain(&domains, seen, cert.Subject.CommonName)
	}
	return domains
}

func addCertificateDomain(domains *[]string, seen map[string]bool, value string) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if domain == "" || seen[domain] {
		return
	}
	seen[domain] = true
	*domains = append(*domains, domain)
}

func preferredCertificateAccessHost(domains []string) string {
	for _, domain := range domains {
		if certificateDomainCanBeAccessHost(domain) {
			return normalizeAccessHost(domain)
		}
	}
	return ""
}

func certificateDomainCanBeAccessHost(domain string) bool {
	if strings.Contains(domain, "*") {
		return false
	}
	host := normalizeAccessHost(domain)
	return host != "" && !strings.ContainsAny(host, " /\\")
}

func (s *Server) applyCertificateAccessHost(ctx context.Context, host string) error {
	normalized := normalizeAccessHost(host)
	if normalized == "" {
		return nil
	}
	publicBaseURL := normalizePublicBaseURLForHost(s.cfg.PublicBaseURL, normalized, s.configuredAccessScheme())
	if publicBaseURL == "" {
		publicBaseURL = s.publicBaseURLForHost(normalized)
	}
	if err := s.persistRuntimeSetting(ctx, "access_host", normalized); err != nil {
		return err
	}
	if err := s.persistRuntimeSetting(ctx, "public_base_url", publicBaseURL); err != nil {
		return err
	}
	if err := s.CleanupIdentitySourcePublicBaseURLs(ctx); err != nil {
		return internalError(err)
	}
	return nil
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
