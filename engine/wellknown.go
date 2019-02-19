package engine

import (
	"net/http"

	"gopkg.in/square/go-jose.v2"

	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
)

// WellKnown represents important OpenID Connect discovery metadata
//
// It includes links to several endpoints (e.g. /oauth2/token) and exposes information on supported signature algorithms
// among others.
type WellKnown struct {
	// URL using the https scheme with no query or fragment component that the OP asserts as its IssuerURL Identifier.
	// If IssuerURL discovery is supported , this value MUST be identical to the issuer value returned
	// by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this IssuerURL.
	//
	// required: true
	// example: https://playground.ory.sh/ory-hydra/public/
	Issuer string `json:"issuer"`

	// URL of the OP's OAuth 2.0 Authorization Endpoint.
	//
	// required: true
	// example: https://playground.ory.sh/ory-hydra/public/oauth2/auth
	AuthURL string `json:"authorization_endpoint"`

	// URL of the OP's Dynamic Client Registration Endpoint.
	// example: https://playground.ory.sh/ory-hydra/admin/client
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// URL of the OP's OAuth 2.0 Token Endpoint
	//
	// required: true
	// example: https://playground.ory.sh/ory-hydra/public/oauth2/token
	TokenURL string `json:"token_endpoint"`

	// URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate
	// signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs
	// to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use)
	// parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
	// Although some algorithms allow the same key to be used for both signatures and encryption, doing so is
	// NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of
	// keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
	//
	// required: true
	// example: https://playground.ory.sh/ory-hydra/public/.well-known/jwks.json
	JWKsURI string `json:"jwks_uri"`

	// JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include
	// pairwise and public.
	//
	// required: true
	// example: public, pairwise
	SubjectTypes []string `json:"subject_types_supported"`

	// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID
	// Providers MUST support the code, id_token, and the token id_token Response Type values.
	//
	// required: true
	ResponseTypes []string `json:"response_types_supported"`

	// JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply
	// values for. Note that for privacy or other reasons, this might not be an exhaustive list.
	ClaimsSupported []string `json:"claims_supported"`

	// JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
	ResponseModesSupported []string `json:"response_modes_supported"`

	// URL of the OP's UserInfo Endpoint.
	UserinfoEndpoint string `json:"userinfo_endpoint"`

	// SON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST
	// support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used
	ScopesSupported []string `json:"scopes_supported"`

	// JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are
	// client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	//	JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported"`

	// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token
	// to encode the Claims in a JWT.
	//
	// required: true
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// 	Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
	RequestParameterSupported bool `json:"request_parameter_supported"`

	// Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`

	// Boolean value specifying whether the OP requires any request_uri values used to be pre-registered
	// using the request_uris registration parameter.
	RequireRequestURIRegistration bool `json:"require_request_uri_registration"`

	// Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support.
	ClaimsParameterSupported bool `json:"claims_parameter_supported"`
}

func wellknownHandler(c *gin.Context) {
	claimsSupported := []string{"sub"}
	scopesSupported := []string{"profile", "openid"}
	subjectTypes := []string{"public"}

	c.JSON(http.StatusOK, &WellKnown{
		Issuer:                            "http://" + ucenter.C.Domain,
		AuthURL:                           "http://" + ucenter.C.Domain + "/oauth2/auth",
		TokenURL:                          "http://" + ucenter.C.Domain + "/oauth2/token",
		JWKsURI:                           "http://" + ucenter.C.Domain + "/.well-known/jwks.json",
		RegistrationEndpoint:              "http://" + ucenter.C.Domain,
		SubjectTypes:                      subjectTypes,
		ResponseTypes:                     []string{"code", "code id_token", "id_token", "token id_token", "token", "token id_token code"},
		ClaimsSupported:                   claimsSupported,
		ScopesSupported:                   scopesSupported,
		UserinfoEndpoint:                  "/oauth2/userinfo",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "private_key_jwt", "none"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		GrantTypesSupported:               []string{"authorization_code", "implicit", "client_credentials", "refresh_token"},
		ResponseModesSupported:            []string{"query", "fragment"},
		UserinfoSigningAlgValuesSupported: []string{"none", "RS256"},
		RequestParameterSupported:         true,
		RequestURIParameterSupported:      true,
		RequireRequestURIRegistration:     true,
	})
}

var jwks = jose.JSONWebKeySet{
	Keys: []jose.JSONWebKey{
		jose.JSONWebKey{
			Key:       &ucenter.SystemRSAKey.PublicKey,
			Algorithm: "RS256",
			Use:       "sig",
			KeyID:     "1",
		},
	},
}

func jwksHandler(c *gin.Context) {
	c.JSON(http.StatusOK, jwks)
}
