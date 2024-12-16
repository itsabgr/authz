package db

import (
	"context"
	"database/sql"
	"time"
)

type Database struct {
	client *sql.DB
}

func NewDatabase(client *sql.DB) *Database {
	return &Database{
		client: client,
	}
}

func (db *Database) Check(ctx context.Context, user, rel, ent string) (int, error) {
	timeout, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	var count int
	err := db.client.QueryRowContext(timeout, "select * from authz_check($1,$2,$3);", user, rel, ent).Scan(&count)
	return count, err
}
