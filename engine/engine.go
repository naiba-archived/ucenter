package engine

import (
	"database/sql"

	"git.cm/naiba/ucenter"
	"github.com/RangelReale/osin"
	mysql "github.com/felipeweb/osin-mysql"
	"github.com/gin-gonic/gin"

	// MySQL Driver
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var (
	// OsinStore osin数据库储存
	OsinStore *mysql.Storage
	// OsinServer osin服务器
	OsinServer *osin.Server
)

func initOsinResource() {
	db, err := sql.Open("mysql", ucenter.DBDSN)
	if err != nil {
		panic(err)
	}

	OsinStore = mysql.New(db, "osin_")
	err = OsinStore.CreateSchemas()
	if err != nil {
		panic(err)
	}
	sconfig := osin.NewServerConfig()
	sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}
	sconfig.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN, osin.PASSWORD, osin.CLIENT_CREDENTIALS, osin.ASSERTION}
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true
	OsinServer = osin.NewServer(sconfig, OsinStore)
}

// ServWeb 开启Web服务
func ServWeb() {
	initOsinResource()
	r := gin.Default()

	r.Use(authorizeMiddleware)

	o := r.Group("oauth2")
	{
		// Authorization code endpoint
		o.Any("auth", oauth2auth)
		// Access token endpoint
		o.Any("token", oauth2token)
	}

	r.Run()
}
