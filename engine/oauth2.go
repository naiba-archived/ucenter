package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/naiba/ucenter/pkg/fosite-storage"

	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/ory/fosite"

	"github.com/RangelReale/osin"
	"github.com/gin-gonic/gin"
)

func introspectionEndpoint(c *gin.Context) {

}

func revokeEndpoint(c *gin.Context) {

}

func oauth2auth(c *gin.Context) {
	ctx := fosite.NewContext()
	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
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
			if len(user.UserAuthorizeds) != 1 || storage.IsArgEqual(ar.GetRequestedScopes(), fosite.Arguments(user.UserAuthorizeds[0].Scope)) {
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
					oauth2provider.WriteAuthorizeError(c.Writer, ar, err)
					return
				}
				perms[scope] = c.PostForm(scope) == "on"
			}
			if !resp.IsError {
				if len(user.UserAuthorizeds) == 0 {
					user.UserAuthorizeds = make([]ucenter.UserAuthorized, 0)
					user.UserAuthorizeds = append(user.UserAuthorizeds, ucenter.UserAuthorized{})
				}
				user.UserAuthorizeds[0].Scope = ar.Scope
				user.UserAuthorizeds[0].Permission = perms
				user.UserAuthorizeds[0].UserID = user.ID
				user.UserAuthorizeds[0].ClientID = ar.Client.GetId()
				user.UserAuthorizeds[0].EncodePermission()
				// 新增授权还是更新授权
				if err := ucenter.DB.Save(&user.UserAuthorizeds[0]).Error; err != nil {
					resp.SetError(osin.E_SERVER_ERROR, err.Error())
				} else {
					// 认证通过标识
					ar.Authorized = true
				}
			}
		} else {
			resp.SetError(osin.E_INVALID_REQUEST, "不支持的请求方式哦。")
		}
		if ar.Authorized && !resp.IsError {
			scop := make([]byte, 0)
			for k, v := range user.UserAuthorizeds[0].Permission {
				if v {
					scop = append(scop, []byte(k+" ")...)
				}
			}
			if len(scop) > 2 {
				ar.Scope = string(scop[:len(scop)-1])
			} else {
				ar.Scope = ""
			}
			// 如果是 OpenIDConnect，特殊照顾
			if user.UserAuthorizeds[0].Permission["openid"] {
				now := time.Now()
				url := ucenter.C.WebProtocol + "://" + ucenter.C.Domain
				idToken := IDToken{
					Issuer:     url,
					UserID:     user.StrID(),
					ClientID:   ar.Client.GetId(),
					Expiration: now.Add(time.Hour).Unix(),
					IssuedAt:   now.Unix(),
					Nonce:      c.Request.URL.Query().Get("nonce"),
				}

				if user.UserAuthorizeds[0].Permission["profile"] {
					idToken.Name = user.Username
					idToken.Bio = user.Bio
					idToken.Avatar = url + "/upload/avatar/" + user.StrID()
				}

				tmp, _ := json.Marshal(idToken)
				ar.UserData = string(tmp)
			}
			osinServer.FinishAuthorizeRequest(resp, c.Request, ar)
		}
	} else {
		// 用户未登录，跳转登录界面
		resp.SetRedirect("/login?return_url=" + url.QueryEscape(c.Request.RequestURI))
	}
	for _, scope := range req.PostForm["scopes"] {
		ar.GrantScope(scope)
	}

	// Now that the user is authorized, we set up a session:
	mySessionData := newSession("peter")

	// When using the HMACSHA strategy you must use something that implements the HMACSessionContainer.
	// It brings you the power of overriding the default values.
	//
	// mySessionData.HMACSession = &strategy.HMACSession{
	//	AccessTokenExpiry: time.Now().Add(time.Day),
	//	AuthorizeCodeExpiry: time.Now().Add(time.Day),
	// }
	//

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

	// It's also wise to check the requested scopes, e.g.:
	// if authorizeRequest.GetScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)

	if resp.IsError && resp.InternalError != nil {
		log.Println("ERROR Oauth2: ", resp.InternalError)
	}

	osin.OutputJSON(resp, c.Writer, c.Request)
}

func oauth2token(c *gin.Context) {
	resp := osinServer.NewResponse()
	defer resp.Close()

	if ar := osinServer.HandleAccessRequest(resp, c.Request); ar != nil {
		switch ar.Type {
		case osin.AUTHORIZATION_CODE:
			ar.Authorized = true
		case osin.REFRESH_TOKEN:
			ar.Authorized = true
		case osin.PASSWORD:
			if ar.Username == "test" && ar.Password == "test" {
				ar.Authorized = true
			}
		case osin.CLIENT_CREDENTIALS:
			ar.Authorized = true
		case osin.ASSERTION:
			if ar.AssertionType == "urn:nb.unknown" && ar.Assertion == "very.newbie" {
				ar.Authorized = true
			}
		}
		osinServer.FinishAccessRequest(resp, c.Request, ar)

		// If an ID Token was encoded as the UserData, serialize and sign it.
		var id IDToken
		if err := json.Unmarshal([]byte(ar.UserData.(string)), &id); err == nil {
			encodeIDToken(resp, id, jwtSigner)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}
