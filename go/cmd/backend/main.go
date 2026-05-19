package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/backend"
	"github.com/dsmpass/dsmpass/go/internal/config"
)

func main() {
	cfg := config.LoadBackend()
	if cfg.RelayHelperHMACSecret == "" {
		log.Fatal("DSMPASS_HELPER_HMAC_SECRET is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	listener, actualListen, err := listenStrict(cfg.Listen)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Listen = actualListen
	if os.Getenv("DSMPASS_PUBLIC_BASE_URL") == "" {
		if port := listenPort(actualListen); port != "" {
			scheme := "https"
			if !cfg.TLSEnabled {
				scheme = "http"
			}
			cfg.PublicBaseURL = scheme + "://" + cfg.AccessHost + ":" + port
		}
	}
	database, queries, err := backend.OpenDatabase(context.Background(), cfg.DatabaseURL)
	if err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}
	defer database.Close()
	server := backend.NewWithDB(cfg, backend.HelperFromConfig(cfg), database, queries)
	if err := server.CleanupIdentitySourcePublicBaseURLs(context.Background()); err != nil {
		log.Printf("failed to clean identity source public base urls: %v", err)
	}
	schedulerContext, stopScheduler := context.WithCancel(context.Background())
	defer stopScheduler()
	server.StartSyncScheduler(schedulerContext)
	log.Printf("DSM Pass backend listening on %s", actualListen)
	log.Printf("DSM Pass public base url: %s", cfg.PublicBaseURL)
	if cfg.AdminAuthEnabled {
		if cfg.AdminSetupRequired {
			log.Printf("admin setup required")
		} else {
			log.Printf("admin username: %s", cfg.AdminUsername)
		}
	}
	if cfg.TLSEnabled || server.IDPTLSEnabled() {
		if err := ensureCertificate(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.AccessHost); err != nil {
			_ = listener.Close()
			log.Fatal(err)
		}
		log.Printf("tls cert=%s key=%s", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if cfg.TLSEnabled {
		log.Printf("admin tls enabled")
	} else {
		log.Printf("admin tls disabled")
	}
	if server.IDPTLSEnabled() {
		log.Printf("idp tls enabled")
	} else {
		log.Printf("idp tls disabled")
	}
	serve(server, listener, actualListen, cfg.TLSEnabled, cfg.TLSCertFile, cfg.TLSKeyFile)
}

func serve(server *backend.Server, adminListener net.Listener, adminListen string, tlsEnabled bool, certFile, keyFile string) {
	idpRoutes := &idpRouteService{
		server:      server,
		adminListen: adminListen,
		certFile:    certFile,
		keyFile:     keyFile,
	}
	server.SetIDPRouteRestarter(idpRoutes.Restart, func(message string) {
		log.Printf("%s", message)
	})
	idpListen := server.IDPListenAddress()
	idpTLSEnabled := server.IDPTLSEnabled()
	if idpListen == "" || listenAddressEqual(idpListen, adminListen) {
		if idpTLSEnabled != tlsEnabled {
			_ = adminListener.Close()
			log.Fatal("idp protocol differs from the management protocol; configure an idp_port different from the management port")
		}
		if err := serveHTTP(adminListener, server.Router(), tlsEnabled, certFile, keyFile); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := idpRoutes.Restart(); err != nil {
		_ = adminListener.Close()
		log.Fatal(err)
	}
	errCh := make(chan error, 2)
	go func() {
		errCh <- serveHTTP(adminListener, server.AdminRouter(), tlsEnabled, certFile, keyFile)
	}()
	log.Fatal(<-errCh)
}

type idpRouteService struct {
	mu          sync.Mutex
	server      *backend.Server
	adminListen string
	certFile    string
	keyFile     string
	httpServer  *http.Server
	listener    net.Listener
}

func (s *idpRouteService) Restart() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.httpServer = nil
	s.listener = nil
	idpListen := s.server.IDPListenAddress()
	if idpListen == "" {
		return net.InvalidAddrError("idp listen address is empty")
	}
	if listenAddressEqual(idpListen, s.adminListen) {
		return net.InvalidAddrError("idp route shares the management port; configure a separate idp_port")
	}
	listener, actualListen, err := listenStrict(idpListen)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Handler: s.server.IDPRouter()}
	idpTLSEnabled := s.server.IDPTLSEnabled()
	s.listener = listener
	s.httpServer = httpServer
	log.Printf("DSM Pass idp listening on %s tls=%t", actualListen, idpTLSEnabled)
	go func() {
		var err error
		if idpTLSEnabled {
			err = httpServer.ServeTLS(listener, s.certFile, s.keyFile)
		} else {
			err = httpServer.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("DSM Pass idp route stopped: %v", err)
		}
	}()
	return nil
}

func serveHTTP(listener net.Listener, handler http.Handler, tlsEnabled bool, certFile, keyFile string) error {
	if tlsEnabled {
		return http.ServeTLS(listener, handler, certFile, keyFile)
	}
	return http.Serve(listener, handler)
}

func ensureCertificate(certFile, keyFile, accessHost string) error {
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "DSM Pass",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(accessHost); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else if accessHost != "" {
		template.DNSNames = append(template.DNSNames, accessHost)
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	certFileHandle, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(certFileHandle, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certFileHandle.Close()
		return err
	}
	if err := certFileHandle.Close(); err != nil {
		return err
	}
	keyFileHandle, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFileHandle, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		_ = keyFileHandle.Close()
		return err
	}
	return keyFileHandle.Close()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func listenStrict(address string) (net.Listener, string, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, "", err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, "", err
	}
	if port <= 1024 {
		return nil, "", net.InvalidAddrError("listen port must be greater than 1024")
	}
	candidate := net.JoinHostPort(host, strconv.Itoa(port))
	listener, err := net.Listen("tcp", candidate)
	if err != nil {
		return nil, "", err
	}
	return listener, candidate, nil
}

func listenPort(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(port)
}

func listenAddressEqual(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(strings.TrimSpace(left))
	rightHost, rightPort, rightErr := net.SplitHostPort(strings.TrimSpace(right))
	if leftErr != nil || rightErr != nil {
		return strings.TrimSpace(left) == strings.TrimSpace(right)
	}
	return leftPort == rightPort && normalizeListenHost(leftHost) == normalizeListenHost(rightHost)
}

func normalizeListenHost(host string) string {
	host = strings.Trim(host, "[] ")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return ""
	}
	return host
}
