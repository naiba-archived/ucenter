package nbgin

import (
	"git.cm/naiba/ucenter"
	"github.com/gin-gonic/gin"
)

// SetCookie 设置Cookie
func SetCookie(c *gin.Context, k, v string) {
	c.SetCookie(k, v, 60*60*24*365*2, "/", ucenter.Domain, false, false)
}
