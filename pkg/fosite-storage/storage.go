package storage

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/jinzhu/gorm"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

const (
	sqlTableOpenID = "openID"
	sqlTableCode   = "code"
)

// FositeStore Fosite 的 Postgres 储存
type FositeStore struct {
	db            *gorm.DB
	HashSignature bool
}

func (s *FositeStore) hashSignature(signature, table string) string {
	if table == "accessToken" && s.HashSignature {
		return fmt.Sprintf("%x", sha512.Sum384([]byte(signature)))
	}
	return signature
}

func sqlDataFromRequest(signature string, r fosite.Requester) (baseSessionTable, error) {
	subject := ""
	if r.GetSession() != nil {
		subject = r.GetSession().GetSubject()
	}

	session, err := json.Marshal(r.GetSession())
	if err != nil {
		return baseSessionTable{}, errors.WithStack(err)
	}

	var challenge sql.NullString
	rr, ok := r.GetSession().(*Session)
	if !ok && r.GetSession() != nil {
		return baseSessionTable{}, errors.Errorf("Expected request to be of type *Session, but got: %T", r.GetSession())
	} else if ok {
		if len(rr.ConsentChallenge) > 0 {
			challenge = sql.NullString{Valid: true, String: rr.ConsentChallenge}
		}
	}

	return baseSessionTable{
		RequestID:         r.GetID(),
		ConsentChallenge:  challenge,
		Signature:         signature,
		RequestedAt:       r.GetRequestedAt(),
		ClientID:          r.GetClient().GetID(),
		Scopes:            pq.StringArray(r.GetRequestedScopes()),
		GrantedScope:      pq.StringArray(r.GetGrantedScopes()),
		GrantedAudience:   pq.StringArray(r.GetGrantedAudience()),
		RequestedAudience: pq.StringArray(r.GetRequestedAudience()),
		Form:              r.GetRequestForm().Encode(),
		Session:           session,
		Subject:           subject,
		Active:            true,
	}, nil
}

func (s *FositeStore) createSession(table, signature string, req fosite.Requester) error {
	var data interface{}
	signature = s.hashSignature(signature, table)
	base, err := sqlDataFromRequest(signature, req)
	if err != nil {
		return err
	}
	switch table {
	case sqlTableOpenID:
		data = &OpenIDSession{&base}
	}
	return s.db.Save(&data).Error
}

func (s *FositeStore) findSessionBySignature(signature string, session fosite.Session, table string) (fosite.Requester, error) {
	signature = s.hashSignature(signature, table)

	var d interface{}
	switch table {
	case sqlTableOpenID:
		d = &OpenIDSession{}
	}
	if err := s.db.Where("signature = ?", signature).First(d).Error; err == gorm.ErrRecordNotFound {
		return nil, errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return nil, err
	} else if !d.(*baseSessionTable).Active && table == sqlTableCode {
		if r, err := d.(*baseSessionTable).toRequest(session, s); err != nil {
			return nil, err
		} else {
			return r, errors.WithStack(fosite.ErrInvalidatedAuthorizeCode)
		}
	} else if !d.(*baseSessionTable).Active {
		return nil, errors.WithStack(fosite.ErrInactiveToken)
	}

	return d.(*baseSessionTable).toRequest(session, s)
}

func (s *FositeStore) deleteSession(signature string, table string) error {
	signature = s.hashSignature(signature, table)

	var err error
	switch table {
	case sqlTableOpenID:
		err = s.db.Delete(&OpenIDSession{}, "signature = ?", signature).Error
	}

	return err
}

// CreateOpenIDConnectSession 创建 OpenID 认证
func (s *FositeStore) CreateOpenIDConnectSession(_ context.Context, signature string, req fosite.Requester) error {
	return s.createSession(sqlTableOpenID, signature, req)
}

// GetOpenIDConnectSession 获取 OpenID 认证
func (s *FositeStore) GetOpenIDConnectSession(_ context.Context, signature string, req fosite.Requester) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, req.GetSession(), sqlTableOpenID)
}

// DeleteOpenIDConnectSession 删除 OpenID 认证
func (s *FositeStore) DeleteOpenIDConnectSession(_ context.Context, signature string) error {
	return s.deleteSession(signature, sqlTableOpenID)
}

func (s *FositeStore) GetClient(_ context.Context, id string) (fosite.Client, error) {

	cl, ok := s.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *FositeStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.AuthorizeCodes[code] = StoreAuthorizeCode{active: true, Requester: req}
	return nil
}

func (s *FositeStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active {
		return rel, fosite.ErrInvalidatedAuthorizeCode
	}

	return rel.Requester, nil
}

func (s *FositeStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return fosite.ErrNotFound
	}
	rel.active = false
	s.AuthorizeCodes[code] = rel
	return nil
}

func (s *FositeStore) DeleteAuthorizeCodeSession(_ context.Context, code string) error {
	delete(s.AuthorizeCodes, code)
	return nil
}

func (s *FositeStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.PKCES[code] = req
	return nil
}

func (s *FositeStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.PKCES[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *FositeStore) DeletePKCERequestSession(_ context.Context, code string) error {
	delete(s.PKCES, code)
	return nil
}

func (s *FositeStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *FositeStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *FositeStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	delete(s.AccessTokens, signature)
	return nil
}

func (s *FositeStore) CreateRefreshTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.RefreshTokens[signature] = req
	s.RefreshTokenRequestIDs[req.GetID()] = signature
	return nil
}

func (s *FositeStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *FositeStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	delete(s.RefreshTokens, signature)
	return nil
}

func (s *FositeStore) CreateImplicitAccessTokenSession(_ context.Context, code string, req fosite.Requester) error {
	s.Implicit[code] = req
	return nil
}

func (s *FositeStore) Authenticate(_ context.Context, name string, secret string) error {
	rel, ok := s.Users[name]
	if !ok {
		return fosite.ErrNotFound
	}
	if rel.Password != secret {
		return errors.New("Invalid credentials")
	}
	return nil
}

func (s *FositeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	if signature, exists := s.RefreshTokenRequestIDs[requestID]; exists {
		s.DeleteRefreshTokenSession(ctx, signature)
		s.DeleteAccessTokenSession(ctx, signature)
	}
	return nil
}

func (s *FositeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	if signature, exists := s.AccessTokenRequestIDs[requestID]; exists {
		s.DeleteAccessTokenSession(ctx, signature)
	}
	return nil
}
