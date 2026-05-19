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
		remoteIP := requestRemoteIP(c.Request)
		allowed, reason := firewallDecision(remoteIP, cidrs(), defaultFirewallPolicy(cidrs()))
		if allowed {
			c.Next()
			return
		}
		s.recordFirewallAccess(c.Request, scope, "deny", reason)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"detail": scope + " access is not allowed from this network"})
	}
}

func allowedByCIDRs(ip net.IP, raw string) bool {
	allowed, _ := firewallDecision(ip, raw, defaultFirewallPolicy(raw))
	return allowed
}

func firewallDecision(ip net.IP, raw, defaultPolicy string) (bool, string) {
	if ip == nil {
		return false, "source ip is invalid"
	}
	if strings.TrimSpace(raw) == "" {
		return defaultPolicyAllows(defaultPolicy), "matched default policy"
	}
	rules, err := parseFirewallRuleList(raw)
	if err != nil {
		return false, "firewall rules are invalid"
	}
	if len(rules) == 0 {
		return defaultPolicyAllows(defaultPolicy), "matched default policy"
	}
	for _, rule := range rules {
		for _, item := range rule.Ranges {
			if item.Contains(ip) {
				if rule.Action == "allow" {
					return true, "matched allow rule"
				}
				return false, "matched ban rule"
			}
		}
	}
	return defaultPolicyAllows(defaultPolicy), "matched default policy"
}

func defaultFirewallPolicy(raw string) string {
	if policy, rules := splitFirewallPolicy(raw); strings.TrimSpace(rules) != "" || policy != "" {
		return policy
	}
	return "allow"
}

func defaultPolicyAllows(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ban", "deny", "drop", "block", "reject", "禁止", "拒绝":
		return false
	default:
		return true
	}
}

func requestRemoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func validateCIDRList(raw, name string) error {
	if _, err := parseFirewallRuleList(raw); err != nil {
		return badRequest(name + " contains invalid firewall rule")
	}
	return nil
}

type firewallRule struct {
	Action string
	Ranges []*net.IPNet
}

func parseFirewallRuleList(raw string) ([]firewallRule, error) {
	_, raw = splitFirewallPolicy(raw)
	lines := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	rules := make([]firewallRule, 0, len(lines))
	for _, line := range lines {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		action, sources := parseFirewallRuleLine(value)
		ranges, err := parseCIDRList(sources)
		if err != nil {
			return nil, err
		}
		rules = append(rules, firewallRule{Action: action, Ranges: ranges})
	}
	if len(rules) == 0 {
		return rules, nil
	}
	return rules, nil
}

func splitFirewallPolicy(raw string) (string, string) {
	lines := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	if len(lines) == 0 {
		return "allow", raw
	}
	first := strings.TrimSpace(lines[0])
	parts := strings.Fields(first)
	if len(parts) >= 2 && strings.EqualFold(parts[0], "default") {
		policy := normalizedFirewallAction(parts[1])
		if policy == "" {
			policy = "allow"
		}
		return policy, strings.Join(lines[1:], "\n")
	}
	if strings.HasPrefix(strings.ToLower(first), "default:") || strings.HasPrefix(strings.ToLower(first), "default=") {
		policy := normalizedFirewallAction(first[len("default:"):])
		if policy == "" {
			policy = "allow"
		}
		return policy, strings.Join(lines[1:], "\n")
	}
	return "allow", raw
}

func parseFirewallRuleLine(value string) (string, string) {
	if action, source, ok := parseCompactFirewallRuleLine(value); ok {
		return action, source
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "allow", value
	}
	switch normalizedFirewallAction(fields[0]) {
	case "allow":
		return "allow", strings.TrimSpace(strings.TrimPrefix(value, fields[0]))
	case "ban":
		return "ban", strings.TrimSpace(strings.TrimPrefix(value, fields[0]))
	default:
		return "allow", value
	}
}

func parseCompactFirewallRuleLine(value string) (string, string, bool) {
	for _, sep := range []string{":", "="} {
		parts := strings.SplitN(value, sep, 2)
		if len(parts) != 2 {
			continue
		}
		action := normalizedFirewallAction(parts[0])
		if action == "" {
			continue
		}
		return action, strings.TrimSpace(parts[1]), true
	}
	return "", "", false
}

func normalizedFirewallAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow", "accept", "permit", "允许", "放行":
		return "allow"
	case "ban", "deny", "drop", "block", "reject", "拒绝", "禁止":
		return "ban"
	default:
		return ""
	}
}

func parseCIDRList(raw string) ([]*net.IPNet, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	ranges := make([]*net.IPNet, 0, len(parts)+4)
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if expanded, ok := cidrAlias(value); ok {
			for _, item := range expanded {
				_, cidr, err := net.ParseCIDR(item)
				if err != nil {
					return nil, err
				}
				ranges = append(ranges, cidr)
			}
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

func cidrAlias(value string) ([]string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "all", "any":
		return []string{"0.0.0.0/0", "::/0"}, true
	case "private", "lan", "local", "intranet", "内网":
		return []string{"127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}, true
	case "loopback", "localhost", "本机":
		return []string{"127.0.0.1/32", "::1/128"}, true
	default:
		return nil, false
	}
}
