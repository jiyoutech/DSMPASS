package backend

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
	"github.com/dsmpass/dsmpass/go/internal/helperclient"
)

type Server struct {
	cfg              config.BackendConfig
	helper           helperclient.Client
	database         *sql.DB
	store            *db.Queries
	logDatabase      *sql.DB
	logStore         *db.Queries
	stateMu          sync.Mutex
	states           map[string]oauthState
	adminMu          sync.Mutex
	syncMu           sync.Mutex
	syncRuns         map[string]bool
	autoSync         map[string]time.Time
	logCleanupMu     sync.Mutex
	lastLogCleanup   time.Time
	idpRouteMu       sync.Mutex
	restartIDPRoute  func() error
	restartIDPNotice func(string)
	tlsRefreshMu     sync.Mutex
	refreshTLS       func(string)
}

const oauthStateTTL = 10 * time.Minute

type oauthState struct {
	ProviderSlug string
	ExpiresAt    time.Time
}

var errUnknownProvider = errors.New("unknown provider")
var errSyncAlreadyRunning = errors.New("sync already running")

func New(cfg config.BackendConfig, helper helperclient.Client, store *db.Queries) *Server {
	return newServer(cfg, helper, nil, store)
}

func NewWithDB(cfg config.BackendConfig, helper helperclient.Client, database *sql.DB, store *db.Queries) *Server {
	server := newServer(cfg, helper, database, store)
	_ = server.LoadRuntimeSettings(context.Background())
	server.refreshAdminSetupState()
	return server
}

func NewWithDatabases(cfg config.BackendConfig, helper helperclient.Client, database *sql.DB, store *db.Queries, logDatabase *sql.DB, logStore *db.Queries) *Server {
	server := newServer(cfg, helper, database, store)
	if logStore != nil {
		server.logDatabase = logDatabase
		server.logStore = logStore
	}
	_ = server.LoadRuntimeSettings(context.Background())
	server.refreshAdminSetupState()
	return server
}

func newServer(cfg config.BackendConfig, helper helperclient.Client, database *sql.DB, store *db.Queries) *Server {
	cfg.RelayMode = "socket"
	return &Server{
		cfg:         cfg,
		helper:      helper,
		database:    database,
		store:       store,
		logDatabase: database,
		logStore:    store,
		states:      map[string]oauthState{},
		syncRuns:    map[string]bool{},
		autoSync:    map[string]time.Time{},
	}
}

func (s *Server) logs() *db.Queries {
	if s.logStore != nil {
		return s.logStore
	}
	return s.store
}

func HelperFromConfig(cfg config.BackendConfig) helperclient.Client {
	return helperclient.NewUnixSocketClient(cfg)
}

func (s *Server) AdminListenAddress() string {
	return s.cfg.Listen
}

func (s *Server) IDPListenAddress() string {
	if s.cfg.IDPListen != "" {
		return s.cfg.IDPListen
	}
	return ""
}

func (s *Server) IDPTLSEnabled() bool {
	return s.configuredAccessScheme() == "https"
}

func (s *Server) SetIDPRouteRestarter(restart func() error, notice func(string)) {
	s.idpRouteMu.Lock()
	defer s.idpRouteMu.Unlock()
	s.restartIDPRoute = restart
	s.restartIDPNotice = notice
}

func (s *Server) SetTLSConnectionRefresher(refresh func(string)) {
	s.tlsRefreshMu.Lock()
	defer s.tlsRefreshMu.Unlock()
	s.refreshTLS = refresh
}

func (s *Server) refreshTLSConnections(scope string) bool {
	s.tlsRefreshMu.Lock()
	refresh := s.refreshTLS
	s.tlsRefreshMu.Unlock()
	if refresh == nil {
		return false
	}
	refresh(scope)
	go func() {
		time.Sleep(500 * time.Millisecond)
		refresh(scope)
	}()
	return true
}

func (s *Server) restartIDPRouteNow(reason string) error {
	s.idpRouteMu.Lock()
	restart := s.restartIDPRoute
	notice := s.restartIDPNotice
	s.idpRouteMu.Unlock()
	if restart == nil {
		return fmt.Errorf("idp route restarter is not configured")
	}
	if notice != nil {
		notice("restarting idp route: " + reason)
	}
	return restart()
}
