package engine

import (
	"net/http"
	"net/url"

	"github.com/lib/pq"

	"github.com/naiba/ucenter/pkg/fosite-storage"

	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/ory/fosite"

	"github.com/gin-gonic/gin"
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
	scopesSupported := []string{"offline", "openid"}
	subjectTypes := []string{"public"}

	c.JSON(http.StatusOK, &WellKnown{
		Issuer:                            "https://" + ucenter.C.Domain,
		AuthURL:                           "https://" + ucenter.C.Domain + "/oauth2/auth",
		TokenURL:                          "https://" + ucenter.C.Domain + "/oauth2/token",
		JWKsURI:                           "https://" + ucenter.C.Domain + "/.well-known/jwks.json",
		RegistrationEndpoint:              "https://" + ucenter.C.Domain,
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

func introspectionEndpoint(c *gin.Context) {
	ctx := fosite.NewContext()
	mySessionData := storage.NewFositeSession("")
	ir, err := oauth2provider.NewIntrospectionRequest(ctx, c.Request, mySessionData)
	if err != nil {
		oauth2provider.WriteIntrospectionError(c.Writer, err)
		return
	}
	oauth2provider.WriteIntrospectionResponse(c.Writer, ir)
}

func revokeEndpoint(c *gin.Context) {
	ctx := fosite.NewContext()
	err := oauth2provider.NewRevocationRequest(ctx, c.Request)
	oauth2provider.WriteRevocationResponse(c.Writer, err)
}

func oauth2auth(c *gin.Context) {
	ctx := fosite.NewContext()
	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		oauth2provider.WriteAuthorizeError(c.Writer, ar, err)
		return
	}

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// We're simplifying things and just checking if the request includes a valid username and password
	user, ok := c.Get(ucenter.AuthUser)
	if ok {
		user := user.(*ucenter.User)
		ucenter.DB.Model(user).Where("client_id = ?", ar.GetClient().GetID()).Association("UserAuthorizeds").Find(&user.UserAuthorizeds)
		if c.Request.Method == http.MethodGet {
			if len(user.UserAuthorizeds) == 0 || !storage.IsArgEqual(ar.GetRequestedScopes(), fosite.Arguments(user.UserAuthorizeds[0].Scope)) {
				// 需要用户授予权限
				var checkPerms = make(map[string]bool)
				for _, scope := range ar.GetRequestedScopes() {
					// 判断scope合法性
					if _, has := ucenter.Scopes[scope]; !has {
						oauth2provider.WriteAuthorizeError(c.Writer, ar, fosite.ErrInvalidRequest)
						break
					}
					if len(user.UserAuthorizeds) == 1 {
						checkPerms[scope] = user.UserAuthorizeds[0].Permission[scope]
					} else {
						checkPerms[scope] = true
					}
				}

				// 权限授予界面
				c.HTML(http.StatusOK, "page/auth", nbgin.Data(c, gin.H{
					"User":   user,
					"Client": ar.GetClient(),
					"Check":  checkPerms,
					"Scopes": ucenter.Scopes,
				}))
				return
			}
		} else if c.Request.Method == http.MethodPost {
			// 用户选择了授权的权限
			var perms = make(map[string]bool)
			for _, scope := range ar.GetRequestedScopes() {
				if _, has := ucenter.Scopes[scope]; !has {
					oauth2provider.WriteAuthorizeError(c.Writer, ar, fosite.ErrInvalidScope)
					return
				}
				gened := c.PostForm(scope) == "on"
				perms[scope] = gened
			}
			if len(user.UserAuthorizeds) == 0 {
				user.UserAuthorizeds = make([]ucenter.UserAuthorized, 0)
				user.UserAuthorizeds = append(user.UserAuthorizeds, ucenter.UserAuthorized{})
			}

			user.UserAuthorizeds[0].Scope = pq.StringArray(ar.GetRequestedScopes())
			user.UserAuthorizeds[0].Permission = perms
			user.UserAuthorizeds[0].UserID = user.ID
			user.UserAuthorizeds[0].ClientID = ar.GetClient().GetID()

			if err := ucenter.DB.Save(&user.UserAuthorizeds[0]).Error; err != nil {
				oauth2provider.WriteAuthorizeError(c.Writer, ar, err)
				return
			}
		} else {
			oauth2provider.WriteAuthorizeError(c.Writer, ar, fosite.ErrInvalidRequest)
			return
		}

		scop := make([]byte, 0)
		for k, v := range user.UserAuthorizeds[0].Permission {
			if v {
				ar.GrantScope(k)
				scop = append(scop, []byte(k+" ")...)
			}
		}
		mySessionData := storage.NewFositeSession(user.StrID())
		response, err := oauth2provider.NewAuthorizeResponse(ctx, ar, mySessionData)
		if err != nil {
			oauth2provider.WriteAuthorizeError(c.Writer, ar, err)
			return
		}

		// Last but not least, send the response!
		oauth2provider.WriteAuthorizeResponse(c.Writer, ar, response)
	} else {
		// 用户未登录，跳转登录界面
		nbgin.SetNoCache(c)
		c.Redirect(http.StatusFound, "/login?return_url="+url.QueryEscape(c.Request.RequestURI))
	}
}

func oauth2token(c *gin.Context) {
	ctx := fosite.NewContext()

	mySessionData := storage.NewFositeSession("")

	accessRequest, err := oauth2provider.NewAccessRequest(ctx, c.Request, mySessionData)

	if err != nil {
		oauth2provider.WriteAccessError(c.Writer, accessRequest, err)
		return
	}

	// If this is a client_credentials grant, grant all scopes the client is allowed to perform.
	if accessRequest.GetGrantTypes().Exact("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			if fosite.HierarchicScopeStrategy(accessRequest.GetClient().GetScopes(), scope) {
				accessRequest.GrantScope(scope)
			}
		}
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		oauth2provider.WriteAccessError(c.Writer, accessRequest, err)
		return
	}

	// All done, send the response.
	oauth2provider.WriteAccessResponse(c.Writer, accessRequest, response)
}
