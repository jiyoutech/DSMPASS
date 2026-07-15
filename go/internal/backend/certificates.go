package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type certificateInfo struct {
	CommonName        string   `json:"common_name"`
	Subject           string   `json:"subject"`
	Issuer            string   `json:"issuer"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	DNSNames          []string `json:"dns_names"`
	Label             string   `json:"label"`
	IsSelfSigned      bool     `json:"is_self_signed"`
	IsTestCertificate bool     `json:"is_test_certificate"`
}

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
	info := certificateInformation(pair)
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
	connectionsRefreshed := s.refreshTLSConnections(scope)
	c.JSON(http.StatusOK, gin.H{
		"success":               true,
		"scope":                 scope,
		"restart_required":      restartRequired,
		"connections_refreshed": connectionsRefreshed,
		"certificate_domains":   domains,
		"certificate_info":      info,
		"applied_access_host":   appliedAccessHost,
	})
}

func (s *Server) certificateTarget(scope string) (string, string, bool, bool) {
	switch scope {
	case "admin":
		return s.cfg.TLSCertFile, s.cfg.TLSKeyFile, false, true
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

func certificateInformation(pair tls.Certificate) certificateInfo {
	if len(pair.Certificate) == 0 {
		return certificateInfo{Label: "未知证书"}
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return certificateInfo{Label: "未知证书"}
	}
	isSelfSigned := cert.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(cert) == nil
	isTestCertificate := certificateLooksLikeTest(cert, isSelfSigned)
	label := "正式证书"
	if isTestCertificate {
		label = "测试证书"
	} else if isSelfSigned {
		label = "自签证书"
	}
	return certificateInfo{
		CommonName:        cert.Subject.CommonName,
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		NotBefore:         cert.NotBefore.Format(time.RFC3339),
		NotAfter:          cert.NotAfter.Format(time.RFC3339),
		DNSNames:          append([]string(nil), cert.DNSNames...),
		Label:             label,
		IsSelfSigned:      isSelfSigned,
		IsTestCertificate: isTestCertificate,
	}
}

func certificateLooksLikeTest(cert *x509.Certificate, isSelfSigned bool) bool {
	values := []string{
		cert.Subject.CommonName,
		strings.Join(cert.Subject.Organization, " "),
		strings.Join(cert.Subject.OrganizationalUnit, " "),
		cert.Issuer.CommonName,
	}
	values = append(values, cert.DNSNames...)
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "测试") || strings.Contains(normalized, "test") {
			return true
		}
		if strings.HasSuffix(normalized, ".local") || strings.HasSuffix(normalized, ".invalid") || strings.HasSuffix(normalized, ".example") {
			return true
		}
	}
	return isSelfSigned && strings.Contains(strings.ToLower(cert.Subject.String()), "dsmpass")
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
	if _, err := tls.X509KeyPair(certData, keyData); err != nil {
		return fmt.Errorf("certificate and private key do not match: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}
	certTemp, err := writeTempCertificateFile(certFile, certData)
	if err != nil {
		return err
	}
	keyTemp, err := writeTempCertificateFile(keyFile, keyData)
	if err != nil {
		_ = os.Remove(certTemp)
		return err
	}
	certBackup, certExisted, err := backupExistingFile(certFile)
	if err != nil {
		_ = os.Remove(certTemp)
		_ = os.Remove(keyTemp)
		return err
	}
	keyBackup, keyExisted, err := backupExistingFile(keyFile)
	if err != nil {
		restoreFile(certFile, certBackup, certExisted)
		_ = os.Remove(certTemp)
		_ = os.Remove(keyTemp)
		return err
	}
	if err := os.Rename(certTemp, certFile); err != nil {
		restoreFile(certFile, certBackup, certExisted)
		restoreFile(keyFile, keyBackup, keyExisted)
		_ = os.Remove(certTemp)
		_ = os.Remove(keyTemp)
		return err
	}
	if err := os.Rename(keyTemp, keyFile); err != nil {
		restoreFile(certFile, certBackup, certExisted)
		restoreFile(keyFile, keyBackup, keyExisted)
		_ = os.Remove(keyTemp)
		return err
	}
	removeBackup(certBackup, certExisted)
	removeBackup(keyBackup, keyExisted)
	return nil
}

func writeTempCertificateFile(target string, data []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*.tmp")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func backupExistingFile(target string) (string, bool, error) {
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	backup, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*.bak")
	if err != nil {
		return "", false, err
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return "", false, err
	}
	if err := os.Remove(backupPath); err != nil {
		return "", false, err
	}
	if err := os.Rename(target, backupPath); err != nil {
		return "", false, err
	}
	return backupPath, true, nil
}

func restoreFile(target, backup string, existed bool) {
	_ = os.Remove(target)
	if existed {
		_ = os.Rename(backup, target)
	}
}

func removeBackup(backup string, existed bool) {
	if existed {
		_ = os.Remove(backup)
	}
}

func (s *Server) restartIDPRouteHandler(c *gin.Context) {
	if err := s.restartIDPRouteNow("manual idp route restart"); err != nil {
		writeError(c, internalError(err))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) refreshTLSConnectionsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success":               true,
		"connections_refreshed": s.refreshTLSConnections("all"),
	})
}
