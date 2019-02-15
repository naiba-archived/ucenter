package engine

import (
	"net/http"
	"strconv"

	"github.com/biezhi/gorm-paginator/pagination"
	"github.com/gin-gonic/gin"
	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/fosite-storage"
	"github.com/naiba/ucenter/pkg/nbgin"
)

func adminIndex(c *gin.Context) {
	var userCount, loginCount, clientCount, authCount int
	ucenter.DB.Model(ucenter.User{}).Count(&userCount)
	ucenter.DB.Model(ucenter.Login{}).Count(&loginCount)
	ucenter.DB.Model(storage.FositeClient{}).Count(&clientCount)
	ucenter.DB.Model(ucenter.UserAuthorized{}).Count(&authCount)
	c.HTML(http.StatusOK, "admin/index", nbgin.Data(c, gin.H{
		"user":   userCount,
		"login":  loginCount,
		"client": clientCount,
		"auth":   authCount,
	}))
}

func adminUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	var users []ucenter.User
	paginator := pagination.Pagging(&pagination.Param{
		DB:      ucenter.DB,
		Page:    page,
		Limit:   limit,
		OrderBy: []string{"id desc"},
		ShowSQL: true,
	}, &users)

	c.HTML(http.StatusOK, "admin/users", nbgin.Data(c, gin.H{
		"users": paginator,
	}))
}

func adminApps(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "15"))
	var appsOrigin []storage.FositeClient
	paginator := pagination.Pagging(&pagination.Param{
		DB:      ucenter.DB,
		Page:    page,
		Limit:   limit,
		OrderBy: []string{"id desc"},
		ShowSQL: true,
	}, &appsOrigin)

	c.HTML(http.StatusOK, "admin/apps", nbgin.Data(c, gin.H{
		"apps": paginator,
	}))
}
