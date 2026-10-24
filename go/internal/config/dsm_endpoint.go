package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/dsmpass/dsmpass/go/internal/securefs"
)

// ResolveDSMLoginAPI follows DSM's root-owned settings on every request so a
// DSM port change does not require editing Helper config or restarting it.
func ResolveDSMLoginAPI(cfg HelperConfig) (string, error) {
	if cfg.DSMNativeConfigPath == "" {
		return cfg.DSMLoginAPI, nil
	}
	if cfg.Privileged {
		if err := securefs.CheckRootPath(cfg.DSMNativeConfigPath); err != nil {
			return "", fmt.Errorf("cannot read trusted DSM port settings: %w", err)
		}
	}
	f, err := os.Open(cfg.DSMNativeConfigPath)
	if err != nil {
		return "", fmt.Errorf("DSM port settings unavailable: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return "", errors.New("cannot read DSM port settings")
	}
	var settings struct {
		Port int `json:"port"`
		SSL  *struct {
			Port int `json:"port"`
		} `json:"ssl"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return "", errors.New("invalid DSM port settings JSON")
	}
	scheme, port := "http", settings.Port
	if settings.SSL != nil {
		scheme, port = "https", settings.SSL.Port
	}
	if port < 1 || port > 65535 {
		return "", errors.New("DSM port settings contain no valid authentication port")
	}
	return scheme + "://127.0.0.1:" + strconv.Itoa(port) + "/webapi/entry.cgi", nil
}
