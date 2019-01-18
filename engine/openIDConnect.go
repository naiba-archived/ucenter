package engine

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/RangelReale/osin"
	"github.com/gin-gonic/gin"
	jose "gopkg.in/square/go-jose.v2"
)

// IDToken 4 OpenIDConnect
type IDToken struct {
	Issuer     string `json:"iss"`
	UserID     string `json:"sub"`
	ClientID   string `json:"aud"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`

	Nonce string `json:"nonce,omitempty"` // Non-manditory fields MUST be "omitempty"

	// Custom claims supported by this server.
	// See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	Avatar string `json:"avatar,omitempty"`
	Name   string `json:"name,omitempty"`
}

// encodeIDToken serializes and signs an ID Token then adds a field to the token response.
func encodeIDToken(resp *osin.Response, idToken IDToken, singer jose.Signer) {
	resp.InternalError = func() error {
		payload, err := json.Marshal(idToken)
		if err != nil {
			return fmt.Errorf("failed to marshal token: %v", err)
		}
		jws, err := jwtSigner.Sign(payload)
		if err != nil {
			return fmt.Errorf("failed to sign token: %v", err)
		}
		raw, err := jws.CompactSerialize()
		if err != nil {
			return fmt.Errorf("failed to serialize token: %v", err)
		}
		resp.Output["id_token"] = raw
		return nil
	}()

	// Record errors as internal server errors.
	if resp.InternalError != nil {
		resp.IsError = true
		resp.ErrorId = osin.E_SERVER_ERROR
	}
}

func openIDConnectDiscovery(c *gin.Context) {
	issuer := "http://localhost:8080"
	// For other example see: https://accounts.google.com/.well-known/openid-configuration
	data := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/auth",
		"token_endpoint":                        issuer + "/oauth2/token",
		"jwks_uri":                              issuer + "/oauth2/publickeys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"claims_supported": []string{
			"aud", "email", "email_verified", "exp",
			"family_name", "given_name", "iat", "iss",
			"locale", "name", "sub",
		},
	}
	c.JSON(http.StatusOK, data)
}

func openIDConnectPublickeys(c *gin.Context) {
	c.JSON(http.StatusOK, openIDPublicKeys)
}
