package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"time"
)

type Authz struct {
	ent.Schema
}

func (Authz) Config() ent.Config {
	return ent.Config{Table: "authz"}
}

func (Authz) Fields() []ent.Field {
	return []ent.Field{
		field.String("user").Immutable(),
		field.String("relation").Immutable(),
		field.String("entity").Immutable(),
		field.Time("expire_at").Nillable().Optional().Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
	}
}

func (Authz) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user", "relation", "entity").Unique(),
		index.Fields("expire_at", "user", "relation", "entity"),
		index.Fields("expire_at"),
	}
}
