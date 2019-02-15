package storage

import (
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/ory/fosite" // Naming the dependency jose is important for go-swagger to work, see https://github.com/go-swagger/go-swagger/issues/1587
	"gopkg.in/square/go-jose.v2"
)

// FositeClient represents an OAuth 2.0 FositeClient.
//
// swagger:model oAuth2Client
type FositeClient struct {
	// ClientID  is the id for this client.
	ClientID string `gorm:"primary_key" json:"client_id"`

	// Name is the human-readable string name of the client to be presented to the
	// end-user during authorization.
	Name string `json:"client_name"`

	// Secret is the client's secret. The secret will be included in the create request as cleartext, and then
	// never again. The secret is stored using BCrypt so it is impossible to recover it. Tell your users
	// that they need to write the secret down as it will not be made available again.
	Secret string `json:"client_secret,omitempty"`

	// RedirectURIs is an array of allowed redirect urls for the client, for example http://mydomain/oauth/callback .
	RedirectURIs pq.StringArray `json:"redirect_uris"`

	// GrantTypes is an array of grant types the client is allowed to use.
	//
	// Pattern: client_credentials|authorization_code|implicit|refresh_token
	GrantTypes pq.StringArray `json:"grant_types"`

	// ResponseTypes is an array of the OAuth 2.0 response type strings that the client can
	// use at the authorization endpoint.
	//
	// Pattern: id_token|code|token
	ResponseTypes pq.StringArray `json:"response_types"`

	// Scope is a string containing a space-separated list of scope values (as
	// described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client
	// can use when requesting access tokens.
	//
	// Pattern: ([a-zA-Z0-9\.\*]+\s?)+
	Scope string `json:"scope"`

	// Audience is a whitelist defining the audiences this client is allowed to request tokens for. An audience limits
	// the applicability of an OAuth 2.0 Access Token to, for example, certain API endpoints. The value is a list
	// of URLs. URLs MUST NOT contain whitespaces.
	Audience pq.StringArray `json:"audience"`

	// Owner is a string identifying the owner of the OAuth 2.0 Client.
	Owner string `json:"owner"`

	// PolicyURI is a URL string that points to a human-readable privacy policy document
	// that describes how the deployment organization collects, uses,
	// retains, and discloses personal data.
	PolicyURI string `json:"policy_uri"`

	// AllowedCORSOrigins are one or more URLs (scheme://host[:port]) which are allowed to make CORS requests
	// to the /oauth/token endpoint. If this array is empty, the sever's CORS origin configuration (`CORS_ALLOWED_ORIGINS`)
	// will be used instead. If this array is set, the allowed origins are appended to the server's CORS origin configuration.
	// Be aware that environment variable `CORS_ENABLED` MUST be set to `true` for this to work.
	AllowedCORSOrigins pq.StringArray `json:"allowed_cors_origins"`

	// TermsOfServiceURI is a URL string that points to a human-readable terms of service
	// document for the client that describes a contractual relationship
	// between the end-user and the client that the end-user accepts when
	// authorizing the client.
	TermsOfServiceURI string `json:"tos_uri"`

	// ClientURI is an URL string of a web page providing information about the client.
	// If present, the server SHOULD display this URL to the end-user in
	// a clickable fashion.
	ClientURI string `json:"client_uri"`

	// LogoURI is an URL string that references a logo for the client.
	LogoURI string `json:"logo_uri"`

	// Contacts is a array of strings representing ways to contact people responsible
	// for this client, typically email addresses.
	Contacts pq.StringArray `json:"contacts"`

	// SecretExpiresAt is an integer holding the time at which the client
	// secret will expire or 0 if it will not expire. The time is
	// represented as the number of seconds from 1970-01-01T00:00:00Z as
	// measured in UTC until the date/time of expiration.
	SecretExpiresAt int `json:"client_secret_expires_at"`

	// SubjectType requested for responses to this Client. The subject_types_supported Discovery parameter contains a
	// list of the supported subject_type values for this server. Valid types include `pairwise` and `public`.
	SubjectType string `json:"subject_type"`

	// URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL references a
	// file with a single JSON array of redirect_uri values.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// URL for the Client's JSON Web Key Set [JWK] document. If the Client signs requests to the Server, it contains
	// the signing key(s) the Server uses to validate signatures from the Client. The JWK Set MAY also contain the
	// Client's encryption keys(s), which are used by the Server to encrypt responses to the Client. When both signing
	// and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced
	// JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for both
	// signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used
	// to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST
	// match those in the certificate.
	JSONWebKeysURI string `json:"jwks_uri,omitempty"`

	// Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the jwks parameter are the same as
	// the jwks_uri parameter, other than that the JWK Set is passed by value, rather than by reference. This parameter
	// is intended only to be used by Clients that, for some reason, are unable to use the jwks_uri parameter, for
	// instance, by native applications that might not have a location to host the contents of the JWK Set. If a Client
	// can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that it does not enable key rotation
	// (which jwks_uri does, as described in Section 10 of OpenID Connect Core 1.0 [OpenID.Core]). The jwks_uri and jwks
	// parameters MUST NOT be used together.
	JSONWebKeys    *jose.JSONWebKeySet `gorm:"-" json:"jwks,omitempty"`
	rawJSONWebKeys string

	// Requested Client Authentication method for the Token Endpoint. The options are client_secret_post,
	// client_secret_basic, private_key_jwt, and none.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// Array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY cache the
	// contents of the files referenced by these URIs and not retrieve them at the time they are used in a request.
	// OPs can require that request_uri values used be pre-registered with the require_request_uri_registration
	// discovery parameter.
	RequestURIs pq.StringArray `json:"request_uris,omitempty"`

	// JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects
	// from this Client MUST be rejected, if not signed with this algorithm.
	RequestObjectSigningAlgorithm string `json:"request_object_signing_alg,omitempty"`

	// JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response will be JWT
	// [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to return the Claims
	// as a UTF-8 encoded JSON object using the application/json content-type.
	UserinfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`

	// CreatedAt returns the timestamp of the client's creation.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// GetID 获取ID
func (c *FositeClient) GetID() string {
	return c.ClientID
}

// GetRedirectURIs 获取跳转链接
func (c *FositeClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetHashedSecret 获取加密密钥
func (c *FositeClient) GetHashedSecret() []byte {
	return []byte(c.Secret)
}

// GetScopes 获取 授权项
func (c *FositeClient) GetScopes() fosite.Arguments {
	return fosite.Arguments(strings.Fields(c.Scope))
}

// GetAudience 获取 Audience
func (c *FositeClient) GetAudience() fosite.Arguments {
	return fosite.Arguments(c.Audience)
}

// GetGrantTypes 获取授权类型
func (c *FositeClient) GetGrantTypes() fosite.Arguments {
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	//
	// JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring
	// that it will restrict itself to using.
	// If omitted, the default is that the Client will use only the authorization_code Grant Type.
	if len(c.GrantTypes) == 0 {
		return fosite.Arguments{"authorization_code"}
	}
	return fosite.Arguments(c.GrantTypes)
}

// GetResponseTypes 获取输出类型
func (c *FositeClient) GetResponseTypes() fosite.Arguments {
	// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
	//
	// <JSON array containing a list of the OAuth 2.0 response_type values that the Client is declaring
	// that it will restrict itself to using. If omitted, the default is that the Client will use
	// only the code Response Type.
	if len(c.ResponseTypes) == 0 {
		return fosite.Arguments{"code"}
	}
	return fosite.Arguments(c.ResponseTypes)
}

// GetOwner 获取所有者
func (c *FositeClient) GetOwner() string {
	return c.Owner
}

// IsPublic 是否公开
func (c *FositeClient) IsPublic() bool {
	return c.TokenEndpointAuthMethod == "none"
}

// GetJSONWebKeysURI 获取公钥URI
func (c *FositeClient) GetJSONWebKeysURI() string {
	return c.JSONWebKeysURI
}

// GetJSONWebKeys 获取公钥
func (c *FositeClient) GetJSONWebKeys() *jose.JSONWebKeySet {
	return c.JSONWebKeys
}

// GetTokenEndpointAuthSigningAlgorithm -
func (c *FositeClient) GetTokenEndpointAuthSigningAlgorithm() string {
	return "RS256"
}

// GetRequestObjectSigningAlgorithm -
func (c *FositeClient) GetRequestObjectSigningAlgorithm() string {
	if c.RequestObjectSigningAlgorithm == "" {
		return "RS256"
	}
	return c.RequestObjectSigningAlgorithm
}

// GetTokenEndpointAuthMethod -
func (c *FositeClient) GetTokenEndpointAuthMethod() string {
	if c.TokenEndpointAuthMethod == "" {
		return "client_secret_basic"
	}
	return c.TokenEndpointAuthMethod
}

// GetRequestURIs -
func (c *FositeClient) GetRequestURIs() []string {
	return c.RequestURIs
}
