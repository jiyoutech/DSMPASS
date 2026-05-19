package backend

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dsmpass/dsmpass/go/internal/buildinfo"
)

func (s *Server) getSettings(c *gin.Context) {
	settings, err := s.effectiveSettings(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, settings)
}

func (s *Server) putSettings(c *gin.Context) {
	var update map[string]any
	if err := c.BindJSON(&update); err != nil {
		writeError(c, badRequest("invalid json"))
		return
	}
	restartRequired, err := s.restartRequiredForSettingsUpdate(update)
	if err != nil {
		writeError(c, err)
		return
	}
	if err := s.updateSettings(c.Request.Context(), update, requestScheme(c)); err != nil {
		writeError(c, err)
		return
	}
	s.getSettings(c)
	if restartRequired {
		s.restartIDPRouteOnly("idp route configuration changed")
	}
}

func (s *Server) discoverSettings(c *gin.Context) {
	var payload struct {
		AccessHost string `json:"access_host"`
		Scheme     string `json:"access_scheme"`
		AdminPort  int    `json:"admin_port"`
		IDPPort    int    `json:"idp_port"`
	}
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid json"})
		return
	}
	host := normalizeAccessHost(payload.AccessHost)
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid access_host"})
		return
	}
	scheme := s.configuredAccessScheme()
	if strings.TrimSpace(payload.Scheme) != "" {
		scheme = normalizedAccessScheme(payload.Scheme, s.cfg.TLSEnabled)
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Discovery probes user-managed DSM/self-signed endpoints.
		}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	currentPublicURL := normalizeURLScheme(requestPublicBaseURL(c), scheme)
	currentPort := publicBaseURLPort(currentPublicURL)
	if payload.IDPPort > 0 {
		currentPort = strconv.Itoa(payload.IDPPort)
	}
	if currentPort == "" {
		currentPort = listenAddressPort(s.cfg.Listen)
	}
	publicCandidates := []string{
		currentPublicURL,
		s.publicBaseURLForHost(host),
	}
	if currentPort != "" {
		publicCandidates = append(publicCandidates,
			scheme+"://"+host+":"+currentPort,
		)
	}
	publicCandidates = append(publicCandidates,
		scheme+"://"+host+":25000",
	)
	publicBaseURL := firstReachableBaseURL(c.Request.Context(), client, publicCandidates, "/healthz")
	dsmRedirectURL := firstReachableBaseURL(c.Request.Context(), client, []string{
		strings.TrimRight(dsmRedirectURLForHostScheme(host, scheme), "/"),
	}, "/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth", isDSMAuthAPIInfo)
	dsmDetected := dsmRedirectURL != ""
	if publicBaseURL == "" {
		publicBaseURL = s.publicBaseURLForHost(host)
	}
	if dsmRedirectURL == "" {
		dsmRedirectURL = dsmRedirectURLForHostScheme(host, scheme)
	}
	dsmRedirectURL = normalizeDSMBaseURL(dsmRedirectURL)
	c.JSON(http.StatusOK, gin.H{
		"access_host":          host,
		"access_scheme":        scheme,
		"admin_port":           firstPositiveInt(payload.AdminPort, parsePortInt(listenAddressPort(s.cfg.Listen)), 25000),
		"idp_port":             firstPositiveInt(payload.IDPPort, parsePortInt(publicBaseURLPort(publicBaseURL)), 25000),
		"public_base_url":      normalizeURLScheme(normalizePublicBaseURL(publicBaseURL, scheme), scheme),
		"dsm_redirect_url":     dsmRedirectURL,
		"helper_dsm_login_api": strings.TrimRight(dsmRedirectURL, "/") + "/webapi/entry.cgi",
		"dsm_detected":         dsmDetected,
	})
}

func firstReachableBaseURL(ctx context.Context, client *http.Client, candidates []string, probePath string, validBody ...func([]byte) bool) string {
	seen := map[string]bool{}
	for _, candidate := range candidates {
		baseURL := normalizeBaseURL(candidate)
		if baseURL == "" || seen[baseURL] {
			continue
		}
		seen[baseURL] = true
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+probePath, nil)
		if err != nil {
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 500 {
			continue
		}
		valid := true
		if len(validBody) > 0 && validBody[0] != nil {
			valid = validBody[0](body)
		}
		if valid {
			return baseURL
		}
	}
	return ""
}

func isDSMAuthAPIInfo(body []byte) bool {
	var parsed struct {
		Success bool `json:"success"`
		Data    map[string]struct {
			Path string `json:"path"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	if !parsed.Success {
		return false
	}
	auth, ok := parsed.Data["SYNO.API.Auth"]
	return ok && strings.TrimSpace(auth.Path) != ""
}

func runtimeSettingAllowed(key string) bool {
	switch key {
	case "access_host", "access_scheme", "idp_port", "public_base_url", "dsm_redirect_url", "dsm_cookie_name", "dsm_cookie_secure", "dsm_cookie_httponly", "dsm_cookie_samesite", "relay_helper_hmac_secret", "helper_dsm_login_mode", "helper_dsm_browser_login_ttl_seconds", "helper_dsm_login_api", "helper_dsm_session", "helper_dsm_format", "helper_dsm_otp_code", "helper_dsm_enable_device_token", "helper_dsm_device_name", "helper_dsm_device_id", "helper_dsm_tls_skip_verify", "helper_dsm_timeout_seconds", "setup_completed":
		return true
	default:
		return false
	}
}

func (s *Server) helperStatus(c *gin.Context) {
	health, err := s.helper.HealthCheck(c.Request.Context())
	response := gin.H{
		"mode":        s.cfg.RelayMode,
		"socket_path": s.cfg.RelayHelperSocket,
		"reachable":   err == nil,
		"details":     health,
	}
	if err != nil {
		response["error"] = err.Error()
	}
	c.JSON(http.StatusOK, response)
}

func (s *Server) version(c *gin.Context) {
	health, err := s.helper.HealthCheck(c.Request.Context())
	helperVersion := ""
	helperReachable := err == nil
	if err == nil {
		if value, _ := health["version"].(string); value != "" {
			helperVersion = value
		}
	}
	response := gin.H{
		"backend_version":  buildinfo.Version,
		"frontend_version": buildinfo.FrontendVersion,
		"helper_version":   helperVersion,
		"helper_reachable": helperReachable,
	}
	if err != nil {
		response["helper_error"] = err.Error()
	}
	c.JSON(http.StatusOK, response)
}
