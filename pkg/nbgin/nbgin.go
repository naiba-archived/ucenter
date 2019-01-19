package nbgin

import (
	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
)

// Data 写入数据
func Data(c *gin.Context, data map[string]interface{}) gin.H {
	u, _ := c.Get(ucenter.AuthUser)
	path := c.MustGet(ucenter.RequestRouter).(string)
	return gin.H{
		"title":   ucenter.RouteTitle[path],
		"user":    u,
		"path":    path,
		"sysname": ucenter.C.SysName,
		"data":    data,
	}
}

// SetCookie 设置Cookie
func SetCookie(c *gin.Context, second int, k, v string) {
	c.SetCookie(k, v, second, "/", ucenter.C.Domain, false, false)
}

// SetNoCache 此页面不准缓存
func SetNoCache(c *gin.Context) {
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
}

// JSRedirect JS跳转
func JSRedirect(c *gin.Context, status int, url string) {
	c.Writer.WriteString(`<script>
	window.location.hrefx="` + url + `"
	</script>`)
	c.Status(status)
}
