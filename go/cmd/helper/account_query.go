package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/dsmpass/dsmpass/go/internal/backend"
	"github.com/dsmpass/dsmpass/go/internal/db"
)

func queryAccount() error {
	if os.Geteuid() == 0 {
		return errors.New("account database queries must run as the unprivileged package user")
	}
	return runAccountQuery(os.Stdin, os.Stdout)
}

func runAccountQuery(input io.Reader, output io.Writer) error {
	var request db.HelperAuthorizationQuery
	limited := &io.LimitedReader{R: input, N: (512 << 10) + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return errors.New("invalid account query")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || limited.N == 0 {
		return errors.New("trailing account query data")
	}
	database, queries, err := backend.OpenDatabaseReader(context.Background(), "sqlite://"+request.DatabasePath)
	if err != nil {
		return errors.New("account database is unavailable")
	}
	defer database.Close()
	if request.Action == "dingtalk_login_roster" {
		roster, err := db.DingTalkLoginRoster(context.Background(), queries, request.SourceSlug)
		result := db.HelperAuthorizationResult{LoginRoster: roster}
		if err != nil {
			result.Error = "query_failed"
		}
		return json.NewEncoder(output).Encode(result)
	}
	if request.Action == "dingtalk_login_binding" {
		match, err := db.DingTalkLoginBinding(context.Background(), queries, request.Username, request.LocalUID)
		result := db.HelperAuthorizationResult{DingTalkLoginMatch: match}
		if err != nil {
			result.Error = "query_failed"
		}
		return json.NewEncoder(output).Encode(result)
	}
	if request.Action == "dingtalk_binding" {
		binding, err := db.DingTalkBindingForName(context.Background(), queries, request.Username)
		result := db.HelperAuthorizationResult{DingTalkBinding: binding}
		if err != nil {
			result.Error = "query_failed"
		}
		return json.NewEncoder(output).Encode(result)
	}
	if request.Action == "enrollment_snapshot" {
		snapshot, err := db.HelperEnrollmentCandidates(context.Background(), queries)
		result := db.HelperAuthorizationResult{Enrollment: snapshot}
		if err != nil {
			result.Error = "query_failed"
		}
		return json.NewEncoder(output).Encode(result)
	}
	allowed, err := db.HelperAccountAllowed(context.Background(), queries, request)
	result := db.HelperAuthorizationResult{Allowed: allowed}
	if errors.Is(err, db.ErrSyncedPasswordSourceConflict) {
		result.Error = "source_conflict"
	} else if err != nil {
		result.Error = "query_failed"
	}
	return json.NewEncoder(output).Encode(result)
}
