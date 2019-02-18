package storage

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/lib/pq"
	"github.com/naiba/ucenter"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	sqlTableOpenID = iota
	sqlTableAccess
	sqlTableRefresh
	sqlTableCode
	sqlTablePKCE
)

// FositeStore Fosite 的 Postgres 储存
type FositeStore struct {
	db            *gorm.DB
	HashSignature bool
}

// NewFositeStore new store
func NewFositeStore(db *gorm.DB, hashSignature bool) *FositeStore {
	return &FositeStore{
		db:            db,
		HashSignature: hashSignature,
	}
}

// Migrate db migrate
func (s *FositeStore) Migrate() error {
	return s.db.AutoMigrate(FositeAccess{}, FositeCode{}, FositeOidc{}, FositePkce{}, FositeRefresh{}, FositeClient{}).Error
}

func (s *FositeStore) hashSignature(signature string, table int) string {
	if table == sqlTableAccess && s.HashSignature {
		return fmt.Sprintf("%x", sha512.Sum384([]byte(signature)))
	}
	return signature
}

func sqlDataFromRequest(signature string, r fosite.Requester) (BaseSessionTable, error) {
	subject := ""
	if r.GetSession() != nil {
		subject = r.GetSession().GetSubject()
	}

	session, err := json.Marshal(r.GetSession())
	if err != nil {
		return BaseSessionTable{}, errors.WithStack(err)
	}

	return BaseSessionTable{
		RequestID:         r.GetID(),
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

func (s *FositeStore) createSession(table int, signature string, req fosite.Requester) error {
	signature = s.hashSignature(signature, table)
	base, err := sqlDataFromRequest(signature, req)
	if err != nil {
		return err
	}

	switch table {
	case sqlTableOpenID:
		return s.db.Save(&FositeOidc{base}).Error
	case sqlTableAccess:
		return s.db.Save(&FositeAccess{base}).Error
	case sqlTablePKCE:
		return s.db.Save(&FositePkce{base}).Error
	case sqlTableRefresh:
		return s.db.Save(&FositeRefresh{base}).Error
	case sqlTableCode:
		return s.db.Save(&FositeCode{base}).Error
	}

	return fosite.ErrInvalidRequest
}

func (s *FositeStore) findSessionBySignature(signature string, session fosite.Session, table int) (fosite.Requester, error) {
	signature = s.hashSignature(signature, table)

	var d interface{}
	switch table {
	case sqlTableOpenID:
		d = &FositeOidc{}
	}
	if err := s.db.Where("signature = ?", signature).First(d).Error; err == gorm.ErrRecordNotFound {
		return nil, errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return nil, err
	} else if !d.(*BaseSessionTable).Active && table == sqlTableCode {
		var r fosite.Requester
		if r, err = d.(*BaseSessionTable).toRequest(session, s); err != nil {
			return nil, err
		}
		return r, errors.WithStack(fosite.ErrInvalidatedAuthorizeCode)
	} else if !d.(*BaseSessionTable).Active {
		return nil, errors.WithStack(fosite.ErrInactiveToken)
	}

	return d.(*BaseSessionTable).toRequest(session, s)
}

func (s *FositeStore) deleteSession(signature string, table int) error {
	signature = s.hashSignature(signature, table)

	var err error
	switch table {
	case sqlTableOpenID:
		err = s.db.Delete(&FositeOidc{}, "signature = ?", signature).Error
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

// CreateAuthorizeCodeSession -
func (s *FositeStore) CreateAuthorizeCodeSession(_ context.Context, signature string, req fosite.Requester) error {
	return s.createSession(sqlTableAccess, signature, req)
}

// GetAuthorizeCodeSession -
func (s *FositeStore) GetAuthorizeCodeSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTableCode)
}

// InvalidateAuthorizeCodeSession 失效accessCode
func (s *FositeStore) InvalidateAuthorizeCodeSession(_ context.Context, signature string) error {
	return s.db.Model(FositeCode{}).Where("signature=?", signature).Update("active", false).Error
}

// DeleteAuthorizeCodeSession -
func (s *FositeStore) DeleteAuthorizeCodeSession(_ context.Context, signature string) error {
	return s.db.Delete(FositeCode{}, "signature=?", signature).Error
}

// CreatePKCERequestSession -
func (s *FositeStore) CreatePKCERequestSession(_ context.Context, signature string, req fosite.Requester) error {
	return s.createSession(sqlTablePKCE, signature, req)
}

// GetPKCERequestSession -
func (s *FositeStore) GetPKCERequestSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTablePKCE)
}

// DeletePKCERequestSession -
func (s *FositeStore) DeletePKCERequestSession(_ context.Context, signature string) error {
	return s.db.Delete(FositePkce{}, "signature=?", signature).Error
}

// CreateAccessTokenSession 创建授权码
func (s *FositeStore) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	return s.createSession(sqlTableAccess, signature, req)
}

// GetAccessTokenSession 获取授权码
func (s *FositeStore) GetAccessTokenSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTableAccess)
}

// DeleteAccessTokenSession 删除授权码
func (s *FositeStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	return s.db.Delete(FositeAccess{}, "signature=?", signature).Error
}

// CreateRefreshTokenSession 创建更新令牌
func (s *FositeStore) CreateRefreshTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	return s.createSession(sqlTableRefresh, signature, req)
}

// GetRefreshTokenSession 获取更新令牌
func (s *FositeStore) GetRefreshTokenSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTableRefresh)
}

// DeleteRefreshTokenSession 删除更新令牌
func (s *FositeStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	return s.db.Delete(FositeRefresh{}, "signature=?", signature).Error
}

// CreateImplicitAccessTokenSession 创建简化授权
func (s *FositeStore) CreateImplicitAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return s.CreateAccessTokenSession(ctx, signature, req)
}

// Authenticate 用户认证
func (s *FositeStore) Authenticate(_ context.Context, id string, secret string) error {
	var u ucenter.User
	if err := s.db.First(&u, "id = ?", id).Error; err == gorm.ErrRecordNotFound {
		return fosite.ErrNotFound
	} else if err != nil {
		return fosite.ErrServerError
	} else if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(secret)) != nil {
		return errors.New("Invalid credentials")
	}
	return nil
}

// RevokeRefreshToken 置刷新令牌失效
func (s *FositeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	var d FositeRefresh

	if err := s.db.First(&d, "request_id=?", requestID).Error; err == gorm.ErrRecordNotFound {
		return fosite.ErrNotFound
	} else if err != nil {
		return fosite.ErrServerError
	}
	s.DeleteRefreshTokenSession(ctx, d.Signature)
	s.DeleteAccessTokenSession(ctx, d.Signature)
	return nil
}

// RevokeAccessToken 删除授权码
func (s *FositeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	var d FositeAccess
	if err := s.db.First(&d, "request_id=?", requestID).Error; err == gorm.ErrRecordNotFound {
		return fosite.ErrNotFound
	} else if err != nil {
		return fosite.ErrServerError
	}
	s.DeleteAccessTokenSession(ctx, d.Signature)
	return nil
}

// GetClient 查找客户端
func (s *FositeStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	var c FositeClient
	if err := s.db.First(&c, "client_id = ?", id).Error; err == gorm.ErrRecordNotFound {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, fosite.ErrServerError
	}
	return &c, nil
}
