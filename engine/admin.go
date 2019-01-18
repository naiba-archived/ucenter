package engine

import (
	"net/http"

	"github.com/naiba/ucenter"

	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter/pkg/nbgin"
)

func adminIndex(c *gin.Context) {
	var userCount, loginCount, clientCount, authCount int
	ucenter.DB.Model(ucenter.User{}).Count(&userCount)
	ucenter.DB.Model(ucenter.Login{}).Count(&loginCount)
	ucenter.DB.Model(ucenter.OsinClient{}).Count(&clientCount)
	ucenter.DB.Model(ucenter.UserAuthorized{}).Count(&authCount)
	c.HTML(http.StatusOK, "admin/index", nbgin.Data(c, gin.H{
		"user":   userCount,
		"login":  loginCount,
		"client": clientCount,
		"auth":   authCount,
	}))
}
