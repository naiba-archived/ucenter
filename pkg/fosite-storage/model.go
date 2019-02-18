package storage

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/lib/pq"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

// BaseSessionTable 基本结构
type BaseSessionTable struct {
	ID                int64 `gorm:"PRIMARY_KEY,UNIQUE_INDEX"`
	Signature         string
	RequestID         string
	RequestedAt       time.Time
	ClientID          string
	Scopes            pq.StringArray `gorm:"type:varchar(255)[]"`
	GrantedScope      pq.StringArray `gorm:"type:varchar(255)[]"`
	RequestedAudience pq.StringArray `gorm:"type:varchar(255)[]"`
	GrantedAudience   pq.StringArray `gorm:"type:varchar(255)[]"`
	Form              string
	Subject           string
	Active            bool
	Session           []byte
}

func (s BaseSessionTable) toRequest(session fosite.Session, cm fosite.ClientManager) (*fosite.Request, error) {
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
	*BaseSessionTable
}

// FositeAccess access
type FositeAccess struct {
	*BaseSessionTable
}

// FositeCode code
type FositeCode struct {
	*BaseSessionTable
}

// FositePkce pkce
type FositePkce struct {
	*BaseSessionTable
}

// FositeRefresh refresh
type FositeRefresh struct {
	*BaseSessionTable
}
