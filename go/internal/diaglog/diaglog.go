package diaglog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var mu sync.Mutex

type Event map[string]any

func Append(dataDir, requestID, stage string, enabled bool, fields Event) {
	if dataDir == "" || !enabled {
		return
	}
	event := Event{
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
		"request_id": requestID,
		"stage":      stage,
	}
	for key, value := range fields {
		event[key] = redactValue(key, value)
	}
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dataDir, "login-diagnostics.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(formatEvent(event) + "\n")
}

func redactValue(key string, value any) any {
	if isSensitiveKey(key) {
		return "[REDACTED]"
	}
	switch typed := value.(type) {
	case Event:
		clean := Event{}
		for childKey, childValue := range typed {
			clean[childKey] = redactValue(childKey, childValue)
		}
		return clean
	case map[string]any:
		clean := map[string]any{}
		for childKey, childValue := range typed {
			clean[childKey] = redactValue(childKey, childValue)
		}
		return clean
	case []any:
		clean := make([]any, len(typed))
		for i, childValue := range typed {
			clean[i] = redactValue(key, childValue)
		}
		return clean
	default:
		return value
	}
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(key)
	for _, marker := range []string{
		"password",
		"passwd",
		"secret",
		"token",
		"sid",
		"cookie",
		"signature",
		"shadow",
		"original_line",
		"temp_line",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func formatEvent(event Event) string {
	keys := make([]string, 0, len(event))
	for key := range event {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	line := ""
	for _, key := range keys {
		if line != "" {
			line += " "
		}
		line += key + "=" + formatValue(event[key])
	}
	return line
}

func formatValue(value any) string {
	switch typed := value.(type) {
	case string:
		raw, _ := json.Marshal(typed)
		return string(raw)
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(raw)
	}
}
