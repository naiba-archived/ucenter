package nbgin

import (
	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
)

var (
	titleMap = map[string]string{
		"/":            "个人中心",
		"/login":       "用户登录",
		"/signup":      "用户注册",
		"/oauth2/auth": "用户授权",
	}
)

// Data 写入数据
func Data(c *gin.Context, data map[string]interface{}) gin.H {
	u, _ := c.Get(ucenter.AuthUser)
	return gin.H{
		"title": titleMap[c.MustGet(ucenter.RequestRouter).(string)],
		"user":  u,
		"data":  data,
	}
}

// SetCookie 设置Cookie
func SetCookie(c *gin.Context, k, v string) {
	c.SetCookie(k, v, 60*60*24*365*2, "/", ucenter.Domain, false, false)
}

// SetNoCache 此页面不准缓存
func SetNoCache(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
}
