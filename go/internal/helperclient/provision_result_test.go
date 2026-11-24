package helperclient

import (
	"errors"
	"testing"
)

func TestProvisionResultRequiresExplicitInitialPasswordConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response map[string]any
		password string
		err      error
		want     ProvisionUserResult
	}{
		{"new", map[string]any{"created": true, "initial_password_applied": true}, "supplied", nil, ProvisionUserResult{true, true}},
		{"old helper", map[string]any{"created": true}, "supplied", nil, ProvisionUserResult{Created: true}},
		{"legacy empty success", map[string]any{}, "supplied", nil, ProvisionUserResult{Created: true}},
		{"missing creation", map[string]any{"initial_password_applied": true}, "supplied", nil, ProvisionUserResult{Created: true}},
		{"existing user", map[string]any{"created": false, "initial_password_applied": true}, "supplied", nil, ProvisionUserResult{}},
		{"generated password", map[string]any{"created": true, "initial_password_applied": true}, "", nil, ProvisionUserResult{Created: true}},
		{"malformed confirmation", map[string]any{"created": true, "initial_password_applied": "true"}, "supplied", nil, ProvisionUserResult{Created: true}},
		{"failed request", nil, "supplied", errors.New("fixture error"), ProvisionUserResult{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := provisionUserResult(tc.response, tc.password, tc.err)
			if got != tc.want || err != tc.err {
				t.Fatalf("result %+v, %v", got, err)
			}
		})
	}
}
