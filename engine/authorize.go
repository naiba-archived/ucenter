package engine

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/RangelReale/osin"

	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
)

func anonymousMustLogin(c *gin.Context) {
	_, ok := c.Get(ucenter.AuthUser)
	log.Println(ok)
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, "/login?return_url="+url.QueryEscape(c.Request.RequestURI))
		c.Abort()
	}
}

func authorizeMiddleware(c *gin.Context) {
	//http://localhost:8080/oauth2/auth?response_type=code&client_id=1234&state=xyz&scope=baseinfo,test&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fappauth%2Fcode
	// 跳过无需认证的路由
	url := c.Request.URL.Path
	for _, p := range c.Params {
		url = strings.Replace(url, p.Value, ":"+p.Key, 1)
	}
	c.Set(ucenter.RequestRouter, url)
	if _, has := ucenter.RouterSkipAuthorize[url]; has {
		return
	}
	var authorizedUser *ucenter.User
	// 1. 从 Cookie 认证
	tk, err := c.Cookie(ucenter.AuthCookieName)
	if err == nil {
		var loginClient ucenter.Login
		if ucenter.DB.Preload("User").Where("token = ?", tk).First(&loginClient).Error == nil {
			authorizedUser = &loginClient.User
			c.Set(ucenter.AuthType, ucenter.AuthTypeCookie)
		}
	}
	// 2. 从 AccessToken 认证
	bearer := osin.CheckBearerAuth(c.Request)
	if bearer != nil {
		ad, err := osinStore.LoadAccess(bearer.Code)
		if err == nil && ad != nil && !ad.IsExpired() && ad.UserData != nil {
			user := ad.UserData.(ucenter.User)
			authorizedUser = &user
			c.Set(ucenter.AuthType, ucenter.AuthTypeAccessToken)
		}
	}
	if authorizedUser != nil {
		c.Set(ucenter.AuthUser, authorizedUser)
	}
}
