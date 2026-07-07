package backend

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func requestPublicBaseURL(c *gin.Context) string {
	proto := requestScheme(c)
	host := requestHost(c)
	return strings.TrimRight(proto+"://"+host, "/")
}

func requestHost(c *gin.Context) string {
	return strings.TrimSpace(c.Request.Host)
}

func (s *Server) trustedPublicBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
}

func requestScheme(c *gin.Context) string {
	proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto"))
	if proto == "" {
		if c.Request.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if proto != "https" {
		return "http"
	}
	return "https"
}

func effectivePublicBaseURL(configured, fallback string) string {
	configured = strings.TrimRight(strings.TrimSpace(configured), "/")
	fallback = strings.TrimRight(strings.TrimSpace(fallback), "/")
	if configured == "" || isLoopbackBaseURL(configured) {
		return fallback
	}
	return configured
}

func isLoopbackBaseURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeAccessHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Host
		}
	}
	if index := strings.Index(value, "/"); index >= 0 {
		value = value[:index]
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[] ")
}

func asRuntimeString(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func (s *Server) publicBaseURLForHost(host string) string {
	port := publicBaseURLPort(s.cfg.PublicBaseURL)
	if port == "" {
		port = listenAddressPort(s.cfg.Listen)
	}
	if port == "" {
		port = "25000"
	}
	scheme := s.configuredAccessScheme()
	return scheme + "://" + normalizeAccessHost(host) + ":" + port
}

func dsmRedirectURLForHost(host string) string {
	return dsmRedirectURLForHostScheme(host, "https")
}

func dsmRedirectURLForHostScheme(host, scheme string) string {
	if normalizedAccessScheme(scheme, true) == "http" {
		return "http://" + normalizeAccessHost(host) + ":5000/"
	}
	return "https://" + normalizeAccessHost(host) + ":5001/"
}

func dsmLoginAPIForHost(host string) string {
	return strings.TrimRight(dsmRedirectURLForHost(host), "/") + "/webapi/entry.cgi"
}

func dsmLoginAPIForHostScheme(host, scheme string) string {
	return strings.TrimRight(dsmRedirectURLForHostScheme(host, scheme), "/") + "/webapi/entry.cgi"
}

func requestDSMRedirectURL(c *gin.Context, configured string) string {
	host := normalizeAccessHost(requestHost(c))
	if host == "" {
		return normalizeDSMBaseURL(configured)
	}
	return replaceURLHost(normalizeDSMBaseURL(configured), host, dsmRedirectURLForHost(host))
}

func requestDSMLoginAPI(c *gin.Context, configured string) string {
	host := normalizeAccessHost(requestHost(c))
	if host == "" {
		return normalizeDSMAPIURL(configured)
	}
	return replaceURLHost(normalizeDSMAPIURL(configured), host, dsmLoginAPIForHost(host))
}

func replaceURLHost(value, host, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return fallback
	}
	port := parsed.Port()
	parsed.Host = host
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	}
	return parsed.String()
}

func normalizeDSMBaseURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.TrimRight(value, "/") + "/"
}

func normalizeDSMAPIURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "//webapi/", "/webapi/")
	return strings.TrimRight(value, "/")
}

func publicBaseURLPort(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return parsed.Port()
}

func publicBaseURLScheme(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		return parsed.Scheme
	}
	return ""
}

func normalizeBaseURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func normalizePublicBaseURLForHost(value, host, fallbackScheme string) string {
	value = normalizeBaseURL(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return value
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		parsed.Scheme = fallbackScheme
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		parsed.Scheme = "http"
	}
	normalizedHost := normalizeAccessHost(host)
	if normalizedHost != "" {
		port := parsed.Port()
		parsed.Host = normalizedHost
		if port != "" {
			parsed.Host = net.JoinHostPort(normalizedHost, port)
		}
	}
	return normalizeBaseURL(parsed.String())
}

func normalizePublicBaseURL(value, fallbackScheme string) string {
	value = normalizeBaseURL(value)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		parsed.Scheme = normalizedAccessScheme(fallbackScheme, true)
	}
	return normalizeBaseURL(parsed.String())
}

func normalizeURLScheme(value, scheme string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return value
	}
	parsed.Scheme = normalizedAccessScheme(scheme, parsed.Scheme == "https")
	return parsed.String()
}

func normalizeDSMDefaultPortForScheme(value, scheme, fallbackHost string, api bool) string {
	value = strings.TrimSpace(value)
	if value == "" {
		if api {
			return dsmLoginAPIForHostScheme(fallbackHost, scheme)
		}
		return dsmRedirectURLForHostScheme(fallbackHost, scheme)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		if api {
			return normalizeDSMAPIURL(normalizeURLScheme(value, scheme))
		}
		return normalizeDSMBaseURL(normalizeURLScheme(value, scheme))
	}
	parsed.Scheme = normalizedAccessScheme(scheme, parsed.Scheme == "https")
	if port := parsed.Port(); port == "5000" || port == "5001" {
		host := normalizeAccessHost(parsed.Hostname())
		if host == "" {
			host = normalizeAccessHost(fallbackHost)
		}
		if host != "" {
			if api {
				return dsmLoginAPIForHostScheme(host, scheme)
			}
			return dsmRedirectURLForHostScheme(host, scheme)
		}
	}
	if api {
		return normalizeDSMAPIURL(parsed.String())
	}
	return normalizeDSMBaseURL(parsed.String())
}

func replaceBaseURLPort(value string, port int) string {
	if port <= 0 {
		return normalizeBaseURL(value)
	}
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" {
		return normalizeBaseURL(value)
	}
	host := parsed.Hostname()
	if host == "" {
		return normalizeBaseURL(value)
	}
	parsed.Host = net.JoinHostPort(host, strconv.Itoa(port))
	return normalizeBaseURL(parsed.String())
}

func normalizedAccessScheme(value string, tlsFallback bool) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http":
		return "http"
	case "https":
		return "https"
	default:
		if tlsFallback {
			return "https"
		}
		return "http"
	}
}

func (s *Server) configuredAccessScheme() string {
	switch strings.ToLower(strings.TrimSpace(s.cfg.AccessScheme)) {
	case "http":
		return "http"
	case "https":
		return "https"
	}
	if scheme := publicBaseURLScheme(s.cfg.PublicBaseURL); scheme != "" {
		return scheme
	}
	return normalizedAccessScheme("", s.cfg.TLSEnabled)
}

func (s *Server) persistPublicBaseURLPolicy(ctx context.Context) error {
	scheme := s.configuredAccessScheme()
	normalized := normalizePublicBaseURL(s.cfg.PublicBaseURL, scheme)
	if normalized == "" || normalized == s.cfg.PublicBaseURL {
		return nil
	}
	s.cfg.PublicBaseURL = normalized
	if err := s.saveSetting(ctx, "public_base_url", normalized); err != nil {
		return err
	}
	return nil
}

func listenAddressPort(value string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return port
}

func replaceListenPort(value, fallback string, port int) string {
	if port <= 0 {
		return strings.TrimSpace(value)
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" {
		host, _, err = net.SplitHostPort(strings.TrimSpace(fallback))
		if err != nil || host == "" {
			host = "0.0.0.0"
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func parsePortInt(value string) int {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port <= 0 {
		return 0
	}
	return port
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
