package identity

import "testing"

func TestReservedDSMNames(t *testing.T) {
	reserved := []string{
		"admin",
		"ADMIN",
		"root",
		"Root",
		"administrator",
		"Administrator",
		"administrators",
		"Administrators",
	}
	for _, name := range reserved {
		if !IsReservedDSMUsername(name) {
			t.Errorf("username %q should be reserved", name)
		}
		if !IsReservedDSMGroupname(name) {
			t.Errorf("group name %q should be reserved", name)
		}
	}
	for _, name := range []string{"alice", "admin-team", "rooted", "system-administrators"} {
		if IsReservedDSMUsername(name) {
			t.Errorf("username %q should not be reserved", name)
		}
		if IsReservedDSMGroupname(name) {
			t.Errorf("group name %q should not be reserved", name)
		}
	}
}
