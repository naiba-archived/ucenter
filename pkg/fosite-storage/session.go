package storage

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/naiba/ucenter"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// FositeSession 授权 FositeSession
type FositeSession struct {
	*openid.DefaultSession `json:"idToken"`
	Extra                  map[string]interface{} `json:"extra"`
	ClientID               string
}

// NewFositeSession 新 Session
func NewFositeSession(subject string) *FositeSession {
	return &FositeSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:  "http://" + ucenter.C.Domain,
				Subject: subject,
			},
			Headers: new(jwt.Headers),
			Subject: subject,
		},
		Extra: map[string]interface{}{},
	}
}

// GetJWTClaims 获取 jwt claims
func (s *FositeSession) GetJWTClaims() jwt.JWTClaimsContainer {
	claims := &jwt.JWTClaims{
		Subject:   s.Subject,
		Issuer:    s.DefaultSession.Claims.Issuer,
		Extra:     map[string]interface{}{"ext": s.Extra},
		ExpiresAt: s.GetExpiresAt(fosite.AccessToken),
		IssuedAt:  time.Now(),
		NotBefore: time.Now(),

		// No need to set the audience because that's being done by fosite automatically.
		// Audience:  s.Audience,

		// The JTI MUST NOT BE FIXED or refreshing tokens will yield the SAME token
		// JTI:       s.JTI,

		// These are set by the DefaultJWTStrategy
		// Scope:     s.Scope,

		// Setting these here will cause the token to have the same iat/nbf values always
		// IssuedAt:  s.DefaultSession.Claims.IssuedAt,
		// NotBefore: s.DefaultSession.Claims.IssuedAt,
	}

	if claims.Extra == nil {
		claims.Extra = map[string]interface{}{}
	}

	claims.Extra["client_id"] = s.ClientID

	return claims
}

// GetJWTHeader 获取 jwt header
func (s *FositeSession) GetJWTHeader() *jwt.Headers {
	return &jwt.Headers{
		Extra: map[string]interface{}{},
	}
}

// Clone 克隆
func (s *FositeSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}
