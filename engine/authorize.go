package engine

import (
	"strings"

	"github.com/RangelReale/osin"

	"git.cm/naiba/ucenter"
	"github.com/gin-gonic/gin"
)

func authorizeMiddleware(c *gin.Context) {
	//http://localhost:8080/oauth2/auth?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fappauth%2Fcode
	// 是否跳过认证
	url := c.Request.URL.Path
	for _, p := range c.Params {
		url = strings.Replace(url, p.Value, ":"+p.Key, 1)
	}
	if _, has := ucenter.RouterSkipAuthorize[url]; has {
		return
	}
	var authorizedUser *ucenter.User
	// 1. 从 Cookie 认证
	tk, err := c.Cookie(ucenter.AuthCookieName)
	if err == nil {
		var loginClient ucenter.LoginClient
		if ucenter.DB.Preload("User").Where("token = ?", tk).First(&loginClient).Error == nil {
			authorizedUser = &loginClient.User
			c.Set(ucenter.AuthType, ucenter.AuthTypeCookie)
		}
	}
	// 2. 从 AccessToken 认证
	bearer := osin.CheckBearerAuth(c.Request)
	if bearer != nil {
		ad, err := OsinStore.LoadAccess(bearer.Code)
		if err == nil && ad != nil && !ad.IsExpired() && ad.UserData != nil {
			user := ad.UserData.(ucenter.User)
			c.Set(ucenter.AuthType, ucenter.AuthTypeAccessToken)
			authorizedUser = &user
		}
	}
	c.Set(ucenter.AuthUser, authorizedUser)
}
