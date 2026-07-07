package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDynamicCertificateLoaderReloadsUpdatedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	writeTestCertificatePair(t, certFile, keyFile, "first.example.com")

	config := dynamicTLSConfig(certFile, keyFile)
	first, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got := certificateCommonName(t, first); got != "first.example.com" {
		t.Fatalf("expected first certificate, got %q", got)
	}

	writeTestCertificatePair(t, certFile, keyFile, "second.example.com")
	second, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got := certificateCommonName(t, second); got != "second.example.com" {
		t.Fatalf("expected reloaded certificate, got %q", got)
	}
}

func TestDynamicCertificateLoaderKeepsCachedCertificateOnReloadError(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	writeTestCertificatePair(t, certFile, keyFile, "stable.example.com")

	config := dynamicTLSConfig(certFile, keyFile)
	if _, err := config.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got := certificateCommonName(t, cert); got != "stable.example.com" {
		t.Fatalf("expected cached certificate, got %q", got)
	}
}

func TestServeHTTPUsesUpdatedTLSCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	writeTestCertificatePair(t, certFile, keyFile, "first.example.com")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveHTTP(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), true, certFile, keyFile)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-errCh:
		case <-time.After(time.Second):
			t.Fatal("https server did not stop")
		}
	})

	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}}
	url := "https://" + listener.Addr().String()
	if got := responseCertificateCommonName(t, client, url); got != "first.example.com" {
		t.Fatalf("expected first certificate, got %q", got)
	}

	writeTestCertificatePair(t, certFile, keyFile, "second.example.com")
	if got := responseCertificateCommonName(t, client, url); got != "second.example.com" {
		t.Fatalf("expected updated certificate, got %q", got)
	}
}

func TestManagedHTTPServerClosesIdleConnections(t *testing.T) {
	managed := newManagedHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	managed.trackConnState(serverConn, http.StateIdle)

	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := clientConn.Read(buffer)
		done <- err
	}()
	managed.CloseIdleConnections()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected idle connection to close")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for idle connection close")
	}
}

func TestEnsureCertificateRejectsExistingMismatchedPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	otherCertFile := filepath.Join(dir, "other.crt")
	otherKeyFile := filepath.Join(dir, "other.key")
	writeTestCertificatePair(t, certFile, keyFile, "first.example.com")
	writeTestCertificatePair(t, otherCertFile, otherKeyFile, "second.example.com")
	otherKey, err := os.ReadFile(otherKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}

	err = ensureCertificate(certFile, keyFile, "first.example.com")
	if err == nil {
		t.Fatal("expected mismatched certificate pair error")
	}
	if !strings.Contains(err.Error(), "invalid or do not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeTestCertificatePair(t *testing.T, certFile, keyFile, commonName string) {
	t.Helper()
	time.Sleep(time.Millisecond)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{commonName},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func certificateCommonName(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("missing certificate")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Subject.CommonName
}

func responseCertificateCommonName(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		t.Fatal("missing peer certificate")
	}
	return response.TLS.PeerCertificates[0].Subject.CommonName
}
