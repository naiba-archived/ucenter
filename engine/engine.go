package engine

import (
	"database/sql"

	"git.cm/naiba/ucenter"
	"git.cm/naiba/ucenter/pkg/nbgin"
	"github.com/RangelReale/osin"
	mysql "github.com/felipeweb/osin-mysql"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

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
	binding.Validator = new(nbgin.DefaultValidator)
	r := gin.Default()
	r.LoadHTMLGlob("template/**/*")

	// 鉴权
	r.Use(authorizeMiddleware)

	// 登录
	r.GET("/login", login)
	r.POST("/login", loginHandler)

	// 注册
	r.GET("/signup", signup)
	r.POST("/signup", signupHandler)

	// Oauth2
	o := r.Group("oauth2")
	{
		// Authorization code endpoint
		o.Any("auth", oauth2auth)
		// Access token endpoint
		o.Any("token", oauth2token)
		o.Any("info", oauth2info)
	}

	r.Run(":8080")
}
