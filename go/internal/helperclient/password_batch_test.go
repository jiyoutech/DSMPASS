package helperclient

import (
	"errors"
	"testing"
)

func TestPasswordBatchResultsRequireEveryIdentityInOrder(t *testing.T) {
	targets := []PasswordResetTarget{{AccountID: "1", Username: "alpha"}, {AccountID: "2", Username: "beta"}}
	a := map[string]any{"dsm_username": "alpha", "account_id": "1", "success": true}
	b := map[string]any{"dsm_username": "beta", "account_id": "2", "success": false, "error_code": "DINGTALK_MEMBERSHIP_ONLY"}
	out, err := passwordResetResults(targets, map[string]any{"user_results": []any{a, b}})
	if err != nil || out[0] != nil || !errors.Is(out[1], ErrDingTalkMembershipOnly) {
		t.Fatalf("%v %v", out, err)
	}
	for _, rows := range [][]any{nil, {a}, {b, a}, {a, a}, {a, map[string]any{"dsm_username": "beta", "account_id": "2"}}} {
		if _, err := passwordResetResults(targets, map[string]any{"user_results": rows}); err == nil {
			t.Fatal("unconfirmed results accepted", rows)
		}
	}
}
