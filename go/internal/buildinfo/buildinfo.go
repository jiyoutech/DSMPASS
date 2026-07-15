package buildinfo

import "strings"

var Version = "dev"
var FrontendVersion = "dev"
var AllowMultipleIdentitySources = "true"

func MultipleIdentitySourcesAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(AllowMultipleIdentitySources)) {
	case "1", "true":
		return true
	default:
		return false
	}
}
