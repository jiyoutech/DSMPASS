package backend

import (
	"net"
	"strconv"
	"strings"
)

const minUserPort = 1025

var tcpPortAvailable = ensureTCPPortAvailable

func validateUserPort(port int, name string) error {
	if port < minUserPort || port > 65535 {
		return badRequest(name + " must be between 1025 and 65535")
	}
	return nil
}

func (s *Server) restartRequiredForSettingsUpdate(update map[string]any) (bool, error) {
	restartRequired := false
	nextScheme := s.configuredAccessScheme()
	if raw, ok := update["access_scheme"]; ok {
		scheme := strings.ToLower(strings.TrimSpace(asRuntimeString(raw)))
		if scheme != "http" && scheme != "https" {
			return false, badRequest("invalid access_scheme")
		}
		nextScheme = scheme
		restartRequired = true
	}
	adminPort := parsePortInt(listenAddressPort(s.AdminListenAddress()))
	nextIDPPort := firstPositiveInt(parsePortInt(listenAddressPort(s.IDPListenAddress())), parsePortInt(publicBaseURLPort(s.cfg.PublicBaseURL)))
	if raw, ok := update["idp_port"]; ok {
		port, valid := runtimeInt(raw)
		if !valid {
			return false, badRequest("invalid idp_port")
		}
		if err := validateUserPort(port, "idp_port"); err != nil {
			return false, err
		}
		if port != nextIDPPort {
			if err := tcpPortAvailable(replaceListenPort("", s.cfg.Listen, port)); err != nil {
				return false, badRequest("idp_port is already in use")
			}
			restartRequired = true
		}
		nextIDPPort = port
	}
	if raw, ok := update["public_base_url"]; ok {
		normalized := normalizePublicBaseURL(asRuntimeString(raw), nextScheme)
		port := parsePortInt(publicBaseURLPort(normalized))
		if port > 0 {
			if err := validateUserPort(port, "public_base_url port"); err != nil {
				return false, err
			}
			if _, hasExplicitIDPPort := update["idp_port"]; !hasExplicitIDPPort && port != nextIDPPort {
				if err := tcpPortAvailable(replaceListenPort("", s.cfg.Listen, port)); err != nil {
					return false, badRequest("public_base_url port is already in use")
				}
				restartRequired = true
				nextIDPPort = port
			}
		}
	}
	if nextScheme == "http" && s.cfg.TLSEnabled && adminPort > 0 && nextIDPPort == adminPort {
		return false, badRequest("idp_port must be different from the management port when idp protocol is http")
	}
	return restartRequired, nil
}

func ensureTCPPortAvailable(address string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	if err := validateUserPort(port, "port"); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return listener.Close()
}
