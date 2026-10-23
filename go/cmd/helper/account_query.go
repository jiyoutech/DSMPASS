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
	decoder := json.NewDecoder(io.LimitReader(input, 16384))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return errors.New("invalid account query")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing account query data")
	}
	database, queries, err := backend.OpenDatabaseReader(context.Background(), "sqlite://"+request.DatabasePath)
	if err != nil {
		return errors.New("account database is unavailable")
	}
	defer database.Close()
	allowed, err := db.HelperAccountAllowed(context.Background(), queries, request)
	result := db.HelperAuthorizationResult{Allowed: allowed}
	if errors.Is(err, db.ErrSyncedPasswordSourceConflict) {
		result.Error = "source_conflict"
	} else if err != nil {
		result.Error = "query_failed"
	}
	return json.NewEncoder(output).Encode(result)
}
