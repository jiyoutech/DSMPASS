package signing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"
)

var ErrBadSignature = errors.New("bad signature")
var ErrExpired = errors.New("timestamp outside allowed skew")
var ErrMissingSecret = errors.New("missing signing secret")

func CanonicalPayload(payload map[string]any) ([]byte, error) {
	clean := make(map[string]any, len(payload))
	for key, value := range payload {
		if key == "signature" {
			continue
		}
		clean[key] = value
	}
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(clean); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buffer.Bytes()), nil
}

func Sign(payload map[string]any, secret string) (string, error) {
	if secret == "" {
		return "", ErrMissingSecret
	}
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func Verify(payload map[string]any, secret string, skewSeconds int64) error {
	signature, ok := payload["signature"].(string)
	if !ok || signature == "" {
		return ErrBadSignature
	}
	expected, err := Sign(payload, secret)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return ErrBadSignature
	}
	if skewSeconds > 0 {
		timestamp, ok := numberAsInt64(payload["timestamp"])
		if !ok {
			return ErrExpired
		}
		if int64(math.Abs(float64(time.Now().Unix()-timestamp))) > skewSeconds {
			return ErrExpired
		}
	}
	return nil
}

func numberAsInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}
