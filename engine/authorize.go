package engine

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/naiba/ucenter/pkg/nbgin"

	"github.com/RangelReale/osin"

	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
)

func anonymousMustLogin(c *gin.Context) {
	_, ok := c.Get(ucenter.AuthUser)
	if !ok {
		c.Redirect(http.StatusTemporaryRedirect, "/login?return_url="+url.QueryEscape(c.Request.RequestURI))
		c.Abort()
	}
}

func authorizeMiddleware(c *gin.Context) {

	// 获取路由path
	url := c.Request.URL.Path
	for _, p := range c.Params {
		url = strings.Replace(url, p.Value, ":"+p.Key, 1)
	}
	c.Set(ucenter.RequestRouter, url)

	// 跳过鉴权的路由
	var val interface{}
	var has bool
	if val, has = ucenter.RouteNeedAuthorize[url]; !has {
		return
	}
	var authorizedUser *ucenter.User

	// 1. 从 Cookie 认证
	tk, err := c.Cookie(ucenter.C.AuthCookieName)
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

	// 高级鉴权路由
	if val != nil {
		var params = make([]interface{}, 0)
		if authorizedUser == nil || !ucenter.RAM.Enforce(append(append(params, authorizedUser.StrID()), val.([]interface{})...)...) {
			c.HTML(http.StatusForbidden, "page/info", gin.H{
				"icon":  "low vision",
				"title": "权限不足",
				"msg":   "您的权限不足以访问此页面哟",
			})
		}
	}

	if authorizedUser != nil {
		if authorizedUser.Status == ucenter.StatusSuspended {
			nbgin.SetCookie(c, -1, ucenter.C.AuthCookieName, "")
			c.HTML(http.StatusForbidden, "page/info", gin.H{
				"icon":  "shield alternate",
				"title": "禁止通行",
				"msg":   "您的账户已被禁用，具体原因请联系管理员。",
			})
			c.Abort()
			return
		}
		c.Set(ucenter.AuthUser, authorizedUser)
	}
}
