package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestUploadIDPCertificateAppliesCertificateDomain(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BackendConfig{
		AccessHost:        "192.0.2.10",
		PublicBaseURL:     "https://192.0.2.10:26000",
		RelayMode:         "socket",
		DSMCookieName:     "id",
		DSMCookieSameSite: "Lax",
		IDPTLSCertFile:    filepath.Join(dir, "idp.crt"),
		IDPTLSKeyFile:     filepath.Join(dir, "idp.key"),
	}
	database, queries, err := OpenDatabase(context.Background(), "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(cfg, testHelper{}, database, queries)
	router := server.Router()

	certPEM, keyPEM := testCertificatePair(t, "login.example.com", "unused.example.com")
	body, contentType := multipartCertificateBody(t, certPEM, keyPEM)
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/admin/settings/certificates/idp", body)
	request.Header.Set("Content-Type", contentType)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected ok, got %d body=%s", response.Code, response.Body.String())
	}

	var payload struct {
		CertificateDomains []string `json:"certificate_domains"`
		AppliedAccessHost  string   `json:"applied_access_host"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AppliedAccessHost != "login.example.com" {
		t.Fatalf("expected applied certificate domain, got %#v", payload)
	}
	if server.cfg.AccessHost != "login.example.com" || server.cfg.PublicBaseURL != "https://login.example.com:26000" {
		t.Fatalf("certificate domain was not applied: access_host=%q public_base_url=%q", server.cfg.AccessHost, server.cfg.PublicBaseURL)
	}
}

func TestPreferredCertificateAccessHostSkipsWildcard(t *testing.T) {
	got := preferredCertificateAccessHost([]string{"*.example.com", "login.example.com"})
	if got != "login.example.com" {
		t.Fatalf("expected non-wildcard domain, got %q", got)
	}
}

func testCertificatePair(t *testing.T, dnsNames ...string) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func multipartCertificateBody(t *testing.T, certPEM, keyPEM []byte) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	certPart, err := writer.CreateFormFile("cert", "server.crt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certPart.Write(certPEM); err != nil {
		t.Fatal(err)
	}
	keyPart, err := writer.CreateFormFile("key", "server.key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyPart.Write(keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body, writer.FormDataContentType()
}
