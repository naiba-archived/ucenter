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
