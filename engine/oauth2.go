package engine

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lib/pq"

	"github.com/naiba/ucenter/pkg/fosite-storage"

	jwt2 "github.com/dgrijalva/jwt-go"
	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"

	"github.com/gin-gonic/gin"
)

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

func userInfo(c *gin.Context) {
	session := storage.NewFositeSession("")
	tokenType, ar, err := oauth2provider.IntrospectToken(c, fosite.AccessTokenFromRequest(c.Request), fosite.AccessToken, session)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	if tokenType != fosite.AccessToken {
		c.AbortWithError(http.StatusUnauthorized, errors.New("Only access tokens are allowed in the authorization header"))
		return
	}

	cli, ok := ar.GetClient().(*storage.FositeClient)
	if !ok {
		c.AbortWithError(http.StatusInternalServerError, fosite.ErrServerError.WithHint("Unable to type assert to *client.Client"))
		return
	}

	if cli.UserinfoSignedResponseAlg == "RS256" {
		interim := ar.GetSession().(*storage.FositeSession).IDTokenClaims().ToMap()

		delete(interim, "nonce")
		delete(interim, "at_hash")
		delete(interim, "c_hash")
		delete(interim, "auth_time")
		delete(interim, "iat")
		delete(interim, "rat")
		delete(interim, "exp")
		delete(interim, "jti")

		token, _, err := oauth2strategy.Generate(c, jwt2.MapClaims(interim), &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": 1,
			},
		})
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Header("Content-Type", "application/jwt")
		c.Writer.Write([]byte(token))
	} else if cli.UserinfoSignedResponseAlg == "" || cli.UserinfoSignedResponseAlg == "none" {
		interim := ar.GetSession().(*storage.FositeSession).IDTokenClaims().ToMap()
		delete(interim, "aud")
		delete(interim, "iss")
		delete(interim, "nonce")
		delete(interim, "at_hash")
		delete(interim, "c_hash")
		delete(interim, "auth_time")
		delete(interim, "iat")
		delete(interim, "rat")
		delete(interim, "exp")
		delete(interim, "jti")

		c.JSON(http.StatusOK, interim)
	} else {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Unsupported userinfo signing algorithm \"%s\"", cli.UserinfoSignedResponseAlg))
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
