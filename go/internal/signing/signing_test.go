package signing

import (
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	payload := map[string]any{
		"action":    "health_check",
		"timestamp": time.Now().Unix(),
	}
	signature, err := Sign(payload, "secret")
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = signature
	if err := Verify(payload, "secret", 60); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	payload := map[string]any{
		"action":    "health_check",
		"timestamp": time.Now().Unix(),
	}
	signature, err := Sign(payload, "secret")
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = signature
	payload["action"] = "relay_login"
	if err := Verify(payload, "secret", 60); err != ErrBadSignature {
		t.Fatalf("expected bad signature, got %v", err)
	}
}
