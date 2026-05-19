package backend

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) adminAccessControl() gin.HandlerFunc {
	return s.accessControl(func() string { return s.cfg.AdminAllowedCIDRs }, "admin")
}

func (s *Server) idpAccessControl() gin.HandlerFunc {
	return s.accessControl(func() string { return s.cfg.IDPAllowedCIDRs }, "idp")
}

func (s *Server) accessControl(cidrs func() string, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if allowedByCIDRs(requestRemoteIP(c.Request), cidrs()) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": scope + " access is not allowed from this network"})
	}
}

func allowedByCIDRs(ip net.IP, raw string) bool {
	if ip == nil {
		return false
	}
	if strings.TrimSpace(raw) == "" {
		return true
	}
	ranges, err := parseCIDRList(raw)
	if err != nil {
		return false
	}
	for _, item := range ranges {
		if item.Contains(ip) {
			return true
		}
	}
	return false
}

func requestRemoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func validateCIDRList(raw, name string) error {
	if _, err := parseCIDRList(raw); err != nil {
		return badRequest(name + " contains invalid CIDR")
	}
	return nil
}

func parseCIDRList(raw string) ([]*net.IPNet, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	ranges := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, net.InvalidAddrError(value)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			value = value + "/" + strconv.Itoa(bits)
		}
		_, cidr, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, cidr)
	}
	if len(ranges) == 0 {
		return nil, net.InvalidAddrError("empty cidr list")
	}
	return ranges, nil
}
