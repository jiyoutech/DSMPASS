package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestAccountQueryUsesFixedProtocolAndFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.PrepareSchema(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO app_identities (id) VALUES ('identity');
INSERT INTO dsm_accounts (id,app_identity_id,dsm_username,dsm_username_norm) VALUES ('account','identity','alice','alice');
INSERT INTO dsm_mapping_entries (id,mapping_type,provider_slug,external_account_id,dsm_account_id) VALUES ('mapping','user','source','external','account');`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action, username string
		allowed          bool
	}{
		{"mapped", "alice", true}, {"mapped", "bob", false}, {"login", "alice", false}, {"DROP TABLE dsm_accounts", "alice", false},
	} {
		request, err := json.Marshal(db.HelperAuthorizationQuery{DatabasePath: path, Action: tc.action, Username: tc.username})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := runAccountQuery(bytes.NewReader(request), &output); err != nil {
			t.Fatal(err)
		}
		var result db.HelperAuthorizationResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Allowed != tc.allowed {
			t.Fatalf("%s: %+v", tc.action, result)
		}
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM dsm_accounts").Scan(&count); err != nil || count != 1 {
		t.Fatal("query protocol changed database")
	}
	for _, input := range []string{"", `{}`, `{"sql":"DELETE FROM dsm_accounts"}`, `{} {}`, strings.Repeat("x", 20000)} {
		var output bytes.Buffer
		if err := runAccountQuery(strings.NewReader(input), &output); err == nil {
			t.Fatalf("malformed query accepted: %q", input[:min(len(input), 60)])
		}
	}
	missing := filepath.Join(t.TempDir(), "must-not-create.db")
	request, err := json.Marshal(db.HelperAuthorizationQuery{DatabasePath: missing, Action: "mapped", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAccountQuery(bytes.NewReader(request), &output); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("reader created database")
	}
	request, err = json.Marshal(db.HelperAuthorizationQuery{DatabasePath: path, Action: "enrollment_snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runAccountQuery(bytes.NewReader(request), &output); err != nil {
		t.Fatal(err)
	}
	var snapshot db.HelperAuthorizationResult
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Error != "" || snapshot.Allowed || snapshot.Enrollment == nil || snapshot.Enrollment.Users == nil || snapshot.Enrollment.Groups == nil || len(snapshot.Enrollment.Users) != 0 {
		t.Fatalf("pending unmapped identity granted in migration snapshot: %+v", snapshot)
	}
}
