package nbgin

import (
	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
)

// SetCookie 设置Cookie
func SetCookie(c *gin.Context, k, v string) {
	c.SetCookie(k, v, 60*60*24*365*2, "/", ucenter.Domain, false, false)
}
