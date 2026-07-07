package settings

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/dsmpass/dsmpass/go/internal/config"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func TestApplyHelperRuntimePrefersDeploymentSettings(t *testing.T) {
	ctx := context.Background()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.PrepareSchema(ctx, database); err != nil {
		t.Fatal(err)
	}
	queries := db.New(database)
	if err := queries.UpsertRuntimeSetting(ctx, db.UpsertRuntimeSettingParams{
		Key:       "helper_dsm_login_api",
		ValueJson: `"https://stale.example.com:5001/webapi/entry.cgi"`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertDeploymentSettings(ctx, db.UpsertDeploymentSettingsParams{
		Mode:              "reverse_proxy",
		AccessHost:        "nas.example.com",
		AccessScheme:      "https",
		IDPPort:           25000,
		PublicBaseURL:     "https://login.example.com",
		DSMRedirectURL:    "https://nas.example.com:5001/",
		HelperDSMLoginAPI: "https://nas.example.com:5001/webapi/entry.cgi",
	}); err != nil {
		t.Fatal(err)
	}

	cfg := ApplyHelperRuntime(ctx, config.HelperConfig{
		DSMLoginAPI: "https://default.example.com:5001/webapi/entry.cgi",
	}, queries)
	if cfg.DSMLoginAPI != "https://nas.example.com:5001/webapi/entry.cgi" {
		t.Fatalf("expected helper to prefer deployment settings, got %q", cfg.DSMLoginAPI)
	}
}
