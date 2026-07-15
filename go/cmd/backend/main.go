package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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
	logDatabaseURL := os.Getenv("DSMPASS_LOG_DATABASE_URL")
	if logDatabaseURL == "" {
		logDatabaseURL = backend.LogDatabaseURL(cfg.DatabaseURL)
	}
	logDatabase, logQueries, err := backend.OpenLogDatabase(context.Background(), logDatabaseURL)
	if err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}
	defer logDatabase.Close()
	if err := backend.MigrateLogsToLogDatabase(context.Background(), database, logDatabase); err != nil {
		_ = listener.Close()
		log.Fatal(err)
	}
	server := backend.NewWithDatabases(cfg, backend.HelperFromConfig(cfg), database, queries, logDatabase, logQueries)
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
	if cfg.TLSEnabled {
		if err := ensureCertificate(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.AccessHost); err != nil {
			_ = listener.Close()
			log.Fatal(err)
		}
		log.Printf("admin tls cert=%s key=%s", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if server.IDPTLSEnabled() {
		if err := ensureCertificate(cfg.IDPTLSCertFile, cfg.IDPTLSKeyFile, cfg.AccessHost); err != nil {
			_ = listener.Close()
			log.Fatal(err)
		}
		log.Printf("idp tls cert=%s key=%s", cfg.IDPTLSCertFile, cfg.IDPTLSKeyFile)
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
	serve(server, listener, actualListen, cfg.AdminRedirectListen, cfg.PublicBaseURL, cfg.TLSEnabled, cfg.TLSCertFile, cfg.TLSKeyFile, cfg.IDPTLSCertFile, cfg.IDPTLSKeyFile)
}

func serve(server *backend.Server, adminListener net.Listener, adminListen, adminRedirectListen, publicBaseURL string, tlsEnabled bool, certFile, keyFile, idpCertFile, idpKeyFile string) {
	tlsConnections := newTLSConnectionRefresher()
	server.SetTLSConnectionRefresher(tlsConnections.Refresh)
	idpRoutes := &idpRouteService{
		server:         server,
		adminListen:    adminListen,
		certFile:       idpCertFile,
		keyFile:        idpKeyFile,
		tlsConnections: tlsConnections,
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
		httpServer := newManagedHTTPServer(server.Router())
		tlsConnections.Register("admin", httpServer)
		tlsConnections.Register("idp", httpServer)
		if err := serveHTTPServer(httpServer.server, adminListener, tlsEnabled, certFile, keyFile); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := idpRoutes.Restart(); err != nil {
		_ = adminListener.Close()
		log.Fatal(err)
	}
	startAdminRedirect(adminRedirectListen, adminListen, publicBaseURL, tlsEnabled, certFile, keyFile, tlsConnections)
	errCh := make(chan error, 2)
	adminServer := newManagedHTTPServer(server.AdminRouter())
	tlsConnections.Register("admin", adminServer)
	go func() {
		errCh <- serveHTTPServer(adminServer.server, adminListener, tlsEnabled, certFile, keyFile)
	}()
	log.Fatal(<-errCh)
}

func startAdminRedirect(redirectListen, adminListen, publicBaseURL string, tlsEnabled bool, certFile, keyFile string, tlsConnections *tlsConnectionRefresher) {
	if strings.TrimSpace(redirectListen) == "" || listenAddressEqual(redirectListen, adminListen) {
		return
	}
	listener, actualListen, err := listenStrict(redirectListen)
	if err != nil {
		log.Printf("DSM Pass admin redirect disabled: %v", err)
		return
	}
	targetBase := strings.TrimRight(publicBaseURL, "/")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetBase+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
	httpServer := newManagedHTTPServer(handler)
	tlsConnections.Register("admin", httpServer)
	log.Printf("DSM Pass admin redirect listening on %s -> %s", actualListen, targetBase)
	go func() {
		if err := serveHTTPServer(httpServer.server, listener, tlsEnabled, certFile, keyFile); err != nil {
			log.Printf("DSM Pass admin redirect stopped: %v", err)
		}
	}()
}

type tlsConnectionRefresher struct {
	mu      sync.Mutex
	servers map[string]map[*managedHTTPServer]struct{}
}

func newTLSConnectionRefresher() *tlsConnectionRefresher {
	return &tlsConnectionRefresher{servers: map[string]map[*managedHTTPServer]struct{}{}}
}

func (r *tlsConnectionRefresher) Register(scope string, server *managedHTTPServer) {
	if r == nil || scope == "" || server == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.servers[scope] == nil {
		r.servers[scope] = map[*managedHTTPServer]struct{}{}
	}
	r.servers[scope][server] = struct{}{}
}

func (r *tlsConnectionRefresher) Unregister(scope string, server *managedHTTPServer) {
	if r == nil || scope == "" || server == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.servers[scope], server)
	if len(r.servers[scope]) == 0 {
		delete(r.servers, scope)
	}
}

func (r *tlsConnectionRefresher) Refresh(scope string) {
	for _, server := range r.serversFor(scope) {
		server.CloseIdleConnections()
	}
}

func (r *tlsConnectionRefresher) serversFor(scope string) []*managedHTTPServer {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[*managedHTTPServer]bool{}
	var servers []*managedHTTPServer
	addScope := func(item string) {
		for server := range r.servers[item] {
			if seen[server] {
				continue
			}
			seen[server] = true
			servers = append(servers, server)
		}
	}
	if scope == "all" {
		for item := range r.servers {
			addScope(item)
		}
		return servers
	}
	addScope(scope)
	return servers
}

type managedHTTPServer struct {
	server *http.Server
	mu     sync.Mutex
	idle   map[net.Conn]struct{}
}

func newManagedHTTPServer(handler http.Handler) *managedHTTPServer {
	managed := &managedHTTPServer{idle: map[net.Conn]struct{}{}}
	managed.server = &http.Server{
		Handler:   handler,
		ConnState: managed.trackConnState,
	}
	return managed
}

func (s *managedHTTPServer) trackConnState(conn net.Conn, state http.ConnState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch state {
	case http.StateIdle:
		s.idle[conn] = struct{}{}
	case http.StateActive, http.StateHijacked, http.StateClosed:
		delete(s.idle, conn)
	}
}

func (s *managedHTTPServer) CloseIdleConnections() {
	if s == nil {
		return
	}
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.idle))
	for conn := range s.idle {
		conns = append(conns, conn)
		delete(s.idle, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type idpRouteService struct {
	mu             sync.Mutex
	server         *backend.Server
	adminListen    string
	certFile       string
	keyFile        string
	tlsConnections *tlsConnectionRefresher
	httpServer     *managedHTTPServer
	listener       net.Listener
}

func (s *idpRouteService) Restart() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpServer != nil {
		if s.tlsConnections != nil {
			s.tlsConnections.Unregister("idp", s.httpServer)
		}
		_ = s.httpServer.server.Close()
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
	httpServer := newManagedHTTPServer(s.server.IDPRouter())
	idpTLSEnabled := s.server.IDPTLSEnabled()
	s.listener = listener
	s.httpServer = httpServer
	if s.tlsConnections != nil {
		s.tlsConnections.Register("idp", httpServer)
	}
	log.Printf("DSM Pass idp listening on %s tls=%t", actualListen, idpTLSEnabled)
	go func() {
		var err error
		if idpTLSEnabled {
			err = serveHTTPServer(httpServer.server, listener, true, s.certFile, s.keyFile)
		} else {
			err = httpServer.server.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("DSM Pass idp route stopped: %v", err)
		}
	}()
	return nil
}

func serveHTTP(listener net.Listener, handler http.Handler, tlsEnabled bool, certFile, keyFile string) error {
	return serveHTTPServer(&http.Server{Handler: handler}, listener, tlsEnabled, certFile, keyFile)
}

func serveHTTPServer(server *http.Server, listener net.Listener, tlsEnabled bool, certFile, keyFile string) error {
	if tlsEnabled {
		server.TLSConfig = dynamicTLSConfig(certFile, keyFile)
		return server.ServeTLS(listener, "", "")
	}
	return server.Serve(listener)
}

func ensureCertificate(certFile, keyFile, accessHost string) error {
	if fileExists(certFile) && fileExists(keyFile) {
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return fmt.Errorf("existing tls certificate and private key are invalid or do not match: %w", err)
		}
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
			CommonName:         "DSMPASS",
			Organization:       []string{"DSMPASS"},
			OrganizationalUnit: []string{"DSM PASS"},
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
