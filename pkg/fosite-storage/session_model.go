package storage

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"time"

	"github.com/lib/pq"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

type baseSessionTable struct {
	ID                int64 `gorm:"primary_key"`
	Signature         string
	RequestID         string
	ConsentChallenge  sql.NullString
	RequestedAt       time.Time
	ClientID          string
	Scopes            pq.StringArray
	GrantedScope      pq.StringArray
	RequestedAudience pq.StringArray
	GrantedAudience   pq.StringArray
	Form              string
	Subject           string
	Active            bool
	Session           []byte
}

func (s *baseSessionTable) toRequest(session fosite.Session, cm fosite.ClientManager) (*fosite.Request, error) {
	if session != nil {
		if err := json.Unmarshal(s.Session, session); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	c, err := cm.GetClient(nil, s.ClientID)
	if err != nil {
		return nil, err
	}

	val, err := url.ParseQuery(s.Form)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := &fosite.Request{
		ID:                s.RequestID,
		RequestedAt:       s.RequestedAt,
		Client:            c,
		RequestedScope:    fosite.Arguments(s.Scopes),
		GrantedScope:      fosite.Arguments(s.GrantedScope),
		RequestedAudience: fosite.Arguments(s.RequestedAudience),
		GrantedAudience:   fosite.Arguments(s.GrantedAudience),
		Form:              val,
		Session:           session,
	}

	return r, nil
}

// FositeOidc oidc
type FositeOidc struct {
	*baseSessionTable
}

// FositeAccess access
type FositeAccess struct {
	*baseSessionTable
}

// FositeCode code
type FositeCode struct {
	*baseSessionTable
}

// FositePkce pkce
type FositePkce struct {
	*baseSessionTable
}

// FositeRefresh refresh
type FositeRefresh struct {
	*baseSessionTable
}
