package backend

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
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
	if err := s.updateSettings(c.Request.Context(), update, requestScheme(c), requestRemoteIP(c.Request)); err != nil {
		writeError(c, err)
		return
	}
	settings, err := s.effectiveSettings(c.Request.Context())
	if err != nil {
		writeError(c, err)
		return
	}
	if restartRequired {
		settings["idp_route_restart_required"] = true
		if err := s.restartIDPRouteNow("idp route configuration changed"); err != nil {
			settings["idp_route_restarted"] = false
			settings["idp_route_restart_error"] = err.Error()
		} else {
			settings["idp_route_restarted"] = true
		}
	}
	c.JSON(http.StatusOK, settings)
}

func (s *Server) discoverSettings(c *gin.Context) {
	var payload struct {
		Mode          string `json:"deployment_mode"`
		AccessHost    string `json:"access_host"`
		Scheme        string `json:"access_scheme"`
		AdminPort     int    `json:"admin_port"`
		IDPPort       int    `json:"idp_port"`
		PublicBaseURL string `json:"public_base_url"`
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
	mode := normalizeDeploymentMode(s.cfg.DeploymentMode)
	if strings.TrimSpace(payload.Mode) != "" {
		if !validDeploymentMode(payload.Mode) {
			c.JSON(http.StatusBadRequest, gin.H{"detail": "invalid deployment_mode"})
			return
		}
		mode = normalizeDeploymentMode(payload.Mode)
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
	adminPort := firstPositiveInt(payload.AdminPort, parsePortInt(listenAddressPort(s.cfg.Listen)), 25000)
	configuredIDPPort := parsePortInt(listenAddressPort(s.IDPListenAddress()))
	idpCandidates := []string{}
	if configuredIDPPort > 0 {
		configuredScheme := s.configuredAccessScheme()
		idpCandidates = append(idpCandidates,
			baseURLForHostPort(configuredScheme, "127.0.0.1", configuredIDPPort),
			baseURLForHostPort(configuredScheme, host, configuredIDPPort),
		)
	}
	if payload.IDPPort >= minUserPort && payload.IDPPort <= 65535 {
		idpCandidates = append(idpCandidates, baseURLForHostPort(scheme, host, payload.IDPPort))
	}
	defaultPort := defaultIDPPortForAdmin(adminPort)
	idpCandidates = append(idpCandidates, baseURLForHostPort(scheme, host, defaultPort))
	idpBaseURL := firstReachableBaseURL(c.Request.Context(), client, idpCandidates, "/idp/healthz", isIDPHealth)
	idpDetected := idpBaseURL != ""
	idpPort := firstPositiveInt(
		parsePortInt(publicBaseURLPort(idpBaseURL)),
		configuredIDPPort,
		payload.IDPPort,
		defaultPort,
	)

	publicBaseURL := ""
	publicBaseURLDetected := false
	if mode == "direct" {
		publicBaseURL = baseURLForHostPort(scheme, host, idpPort)
		publicBaseURLDetected = idpDetected
	} else {
		publicBaseURL = normalizePublicBaseURL(payload.PublicBaseURL, scheme)
		if publicBaseURL == "" {
			publicBaseURL = normalizePublicBaseURL(s.cfg.PublicBaseURL, scheme)
		}
		if publicBaseURL != "" {
			publicBaseURLDetected = firstReachableBaseURL(
				c.Request.Context(),
				client,
				[]string{publicBaseURL},
				"/idp/healthz",
				isIDPHealth,
			) != ""
		}
	}
	dsmRedirectURL := firstReachableBaseURL(c.Request.Context(), client, []string{
		strings.TrimRight(dsmRedirectURLForHostScheme(host, scheme), "/"),
	}, "/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth", isDSMAuthAPIInfo)
	dsmDetected := dsmRedirectURL != ""
	if dsmRedirectURL == "" {
		dsmRedirectURL = dsmRedirectURLForHostScheme(host, scheme)
	}
	dsmRedirectURL = normalizeDSMBaseURL(dsmRedirectURL)
	c.JSON(http.StatusOK, gin.H{
		"deployment_mode":          mode,
		"access_host":              host,
		"access_scheme":            scheme,
		"admin_port":               adminPort,
		"idp_port":                 idpPort,
		"idp_detected":             idpDetected,
		"public_base_url":          publicBaseURL,
		"public_base_url_detected": publicBaseURLDetected,
		"dsm_redirect_url":         dsmRedirectURL,
		"helper_dsm_login_api":     strings.TrimRight(dsmRedirectURL, "/") + "/webapi/entry.cgi",
		"dsm_detected":             dsmDetected,
	})
}

func baseURLForHostPort(scheme, host string, port int) string {
	host = normalizeAccessHost(host)
	if host == "" || port <= 0 {
		return ""
	}
	return normalizedAccessScheme(scheme, false) + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func isIDPHealth(body []byte) bool {
	var parsed struct {
		Status    string `json:"status"`
		Component string `json:"component"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	return parsed.Status == "ok" && parsed.Component == "idp"
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
	case "deployment_mode", "access_host", "access_scheme", "idp_port", "admin_allowed_cidrs", "public_base_url", "dsm_redirect_url", "dsm_cookie_name", "dsm_cookie_secure", "dsm_cookie_httponly", "dsm_cookie_samesite", "relay_helper_hmac_secret", "helper_dsm_login_mode", "helper_dsm_browser_login_ttl_seconds", "helper_dsm_login_api", "helper_dsm_session", "helper_dsm_format", "helper_dsm_otp_code", "helper_dsm_enable_device_token", "helper_dsm_device_name", "helper_dsm_device_id", "helper_dsm_tls_skip_verify", "helper_dsm_timeout_seconds", "setup_completed":
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
