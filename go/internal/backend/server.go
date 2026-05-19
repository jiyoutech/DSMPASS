package backend

import (
	"context"
	"database/sql"
	"errors"
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
	stateMu          sync.Mutex
	states           map[string]oauthState
	adminMu          sync.Mutex
	syncMu           sync.Mutex
	syncRuns         map[string]bool
	autoSync         map[string]time.Time
	idpRouteMu       sync.Mutex
	restartIDPRoute  func() error
	restartIDPNotice func(string)
}

const defaultInitialPassword = "123456"
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

func newServer(cfg config.BackendConfig, helper helperclient.Client, database *sql.DB, store *db.Queries) *Server {
	cfg.RelayMode = "socket"
	return &Server{
		cfg:      cfg,
		helper:   helper,
		database: database,
		store:    store,
		states:   map[string]oauthState{},
		syncRuns: map[string]bool{},
		autoSync: map[string]time.Time{},
	}
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
	if port := parsePortInt(publicBaseURLPort(s.cfg.PublicBaseURL)); port > 0 {
		return replaceListenPort("", s.cfg.Listen, port)
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

func (s *Server) restartIDPRouteOnly(reason string) {
	s.idpRouteMu.Lock()
	restart := s.restartIDPRoute
	notice := s.restartIDPNotice
	s.idpRouteMu.Unlock()
	if restart == nil {
		if notice != nil {
			notice("idp route restart requested but no idp route restarter is configured")
		}
		return
	}
	go func() {
		if notice != nil {
			notice("restarting idp route: " + reason)
		}
		if err := restart(); err != nil && notice != nil {
			notice("failed to restart idp route: " + err.Error())
		}
	}()
}
