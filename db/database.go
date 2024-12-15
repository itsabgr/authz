package db

import (
	"context"
	"database/sql"
	"errors"
	"github.com/itsabgr/authz/db/model"
	"github.com/itsabgr/authz/db/model/authz"
	"github.com/itsabgr/authz/db/model/predicate"
	"slices"
	"time"
)

type Database struct {
	client *model.Client
}

func NewDatabase(modelClient *model.Client) *Database {
	return &Database{
		client: modelClient,
	}
}

func buildCheckQuery(now time.Time, user, rel, ent string) predicate.Authz {

	type ure struct {
		user     string
		relation string
		entity   string
	}

	perms := [...]ure{
		{user, rel, ent},
		{"", rel, ent},
		{user, "", ent},
		{user, rel, ""},
		{user, "", ""},
		{"", rel, ""},
		{"", "", ent},
	}

	filter := make([]predicate.Authz, 0, len(perms))

	for i, perm := range perms {

		if perm.user == "" && perm.relation == "" && perm.entity == "" {
			continue
		}

		exists := slices.ContainsFunc(perms[i+1:], func(perm2 ure) bool {
			return perm.user == perm2.user && perm.relation == perm2.relation && perm.entity == perm2.entity
		})

		if exists {
			continue
		}

		filter = append(filter, authz.And(authz.User(perm.user), authz.Relation(perm.relation), authz.Entity(perm.entity)))

	}

	if len(filter) <= 0 {

		panic("no condition for checking authorization")

	}

	return authz.And(authz.Or(authz.ExpireAtGT(now), authz.ExpireAtIsNil()), authz.Or(filter...))

}

type CheckResult struct {
	user      string
	relation  string
	entity    string
	expireAt  *time.Time
	createdAt time.Time
}

func (cr *CheckResult) User() string {
	return cr.user
}

func (cr *CheckResult) Relation() string {
	return cr.relation
}

func (cr *CheckResult) Entity() string {
	return cr.entity
}

func (cr *CheckResult) ExpireAt() *time.Time {

	if cr.expireAt == nil {
		return nil
	}

	exp := *cr.expireAt

	return &exp

}

func (cr *CheckResult) CreatedAt() time.Time {
	return cr.createdAt
}

func (db *Database) Check(ctx context.Context, user, rel, ent string) (*CheckResult, error) {
	if user == "" || rel == "" || ent == "" {
		return nil, errors.New("empty check arguments")
	}
	return db.check(ctx, db.client.Authz, user, rel, ent)
}

func (db *Database) check(ctx context.Context, client *model.AuthzClient, user, rel, ent string) (*CheckResult, error) {

	record, err := client.Query().Where(buildCheckQuery(time.Now(), user, rel, ent)).
		Select(
			authz.FieldUser,
			authz.FieldRelation,
			authz.FieldEntity,
			authz.FieldExpireAt,
			authz.FieldCreatedAt,
		).
		First(ctx)

	if err != nil {

		if model.IsNotFound(err) {

			return nil, nil

		}

		return nil, err
	}

	return &CheckResult{
		user:      record.User,
		relation:  record.Relation,
		entity:    record.Entity,
		expireAt:  record.ExpireAt,
		createdAt: record.CreatedAt,
	}, nil

}

type DuplicatePermission struct {
	CheckResult CheckResult
}

func (e DuplicatePermission) Error() string {
	return "duplicate permission"
}

func (db *Database) Permit(ctx context.Context, user, rel, ent string, expireAt *time.Time) error {
	tx, err := db.client.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  false,
	})
	rollback := true

	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()

	if err != nil {
		return err
	}

	checkResult, err := db.check(ctx, tx.Authz, user, rel, ent)

	if err != nil {
		return err
	}

	if checkResult != nil {
		return DuplicatePermission{CheckResult: *checkResult}
	}

	if err = db.client.Authz.Create().SetUser(user).SetRelation(rel).SetEntity(ent).SetNillableExpireAt(expireAt).Exec(ctx); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	rollback = false

	return nil

}

func (db *Database) Clean(ctx context.Context) error {
	_, err := db.client.Authz.Delete().Where(authz.And(authz.ExpireAtLTE(time.Now()), authz.ExpireAtNotNil())).Exec(ctx)
	return err
}

func (db *Database) Revoke(ctx context.Context, user, rel, ent *string) error {

	filter := make([]predicate.Authz, 0, 3)

	if user != nil {
		filter = append(filter, authz.User(*user))
	}

	if rel != nil {
		filter = append(filter, authz.Relation(*rel))
	}

	if ent != nil {
		filter = append(filter, authz.Entity(*ent))
	}

	if len(filter) <= 0 {
		panic("no condition for revoking authorization")
	}

	_, err := db.client.Authz.Delete().Where(filter...).Exec(ctx)

	return err

}
