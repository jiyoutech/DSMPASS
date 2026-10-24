package helperclient

import "testing"

func TestHelperReleaseCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name              string
		health            map[string]any
		version, revision string
		valid             bool
	}{
		{"match", map[string]any{"version": "0.8.49", "revision": "new"}, "0.8.49", "new", true},
		{"old-version", map[string]any{"version": "0.8.48", "revision": "new"}, "0.8.49", "new", false},
		{"same-version-old-build", map[string]any{"version": "0.8.49", "revision": "old"}, "0.8.49", "new", false},
		{"legacy-without-revision", map[string]any{"version": "0.8.49"}, "0.8.49", "new", false},
		{"missing-health", nil, "0.8.49", "new", false},
		{"development", nil, "dev", "dev", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckCompatibility(tc.health, tc.version, tc.revision); (err == nil) != tc.valid {
				t.Fatalf("compatibility: %v", err)
			}
		})
	}
}
