package engine

import (
	"database/sql"
	"errors"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/naiba/com"

	"github.com/naiba/ucenter/pkg/ram"

	"github.com/RangelReale/osin"
	"github.com/felipeweb/osin-mysql"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/nbgin"

	// MySQL Driver
	_ "github.com/jinzhu/gorm/dialects/mysql"

	"gopkg.in/square/go-jose.v2"
)

var (
	osinStore        *mysql.Storage
	osinServer       *osin.Server
	openIDPublicKeys *jose.JSONWebKeySet
	jwtSigner        jose.Signer
)

func initOsinResource() {
	db, err := sql.Open("mysql", ucenter.DBDSN)
	if err != nil {
		panic(err)
	}
	osinStore = mysql.New(db, "osin_")
	err = osinStore.CreateSchemas()
	if err != nil {
		panic(err)
	}
	sconfig := osin.NewServerConfig()
	sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}
	sconfig.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN, osin.PASSWORD, osin.CLIENT_CREDENTIALS, osin.ASSERTION}
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true
	osinServer = osin.NewServer(sconfig, osinStore)

	// Configure jwtSigner and public keys.
	privateKey := &jose.JSONWebKey{
		Key:       ucenter.SystemRSAKey,
		Algorithm: "RS256",
		Use:       "sig",
		KeyID:     "1", // KeyID should use the key thumbprint.
	}

	jwtSigner, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		log.Fatalf("failed to create jwtSigner: %v", err)
	}

	openIDPublicKeys = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			jose.JSONWebKey{
				Key:       &ucenter.SystemRSAKey.PublicKey,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     "1",
			},
		},
	}
}

// ServWeb 开启Web服务
func ServWeb() {
	initOsinResource()
	binding.Validator = new(nbgin.DefaultValidator)
	r := gin.Default()
	r.Static("static", "static")
	r.Static("upload", "upload")
	r.SetFuncMap(template.FuncMap{
		"df_allow": func(user *ucenter.User, perm string) bool {
			return ucenter.RAM.Enforce(user.StrID(), ram.DefaultDomain, ram.DefaultProject, perm)
		},
		"allow": func(user *ucenter.User, domain, project, perm string) bool {
			return ucenter.RAM.Enforce(user.StrID(), domain, project, perm)
		},
		"add": func(a, b int) int {
			return a + b
		},
	})
	r.LoadHTMLGlob("template/**/*")

	// 头像 Header
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.RequestURI, "/upload/avatar/") {
			c.Header("Content-Type", "image")
		}
	})

	// 鉴权
	r.Use(authorizeMiddleware)

	// 登录
	r.GET("/login", login)
	r.POST("/login", loginHandler)

	// 注册
	r.GET("/signup", signup)
	r.POST("/signup", signupHandler)

	// 用户中心
	mustLoginRoute := r.Group("")
	mustLoginRoute.Use(anonymousMustLogin)
	{
		mustLoginRoute.GET("/", index)
		mustLoginRoute.GET("/logout", logout)
		mustLoginRoute.PATCH("/", editProfileHandler)
		mustLoginRoute.DELETE("/user/:id", userDelete)
		mustLoginRoute.POST("/app", editOauth2App)
		mustLoginRoute.DELETE("/app/:id", deleteOauth2App)
	}

	// 管理员路由
	admin := mustLoginRoute.Group("/admin")
	{
		admin.GET("/", adminIndex)
		admin.GET("/users", adminUsers)
		admin.GET("/apps", adminApps)
		admin.POST("/user/status", userStatus)
		admin.POST("/app/status", appStatus)
	}

	// Oauth2
	o := r.Group("oauth2")
	{
		// Authorization code endpoint
		o.GET("auth", oauth2auth)
		o.POST("auth", oauth2auth)
		// Access token endpoint
		o.GET("token", oauth2token)
		o.POST("token", oauth2token)
		o.GET("info", oauth2info)
		o.GET("publickeys", openIDConnectPublickeys)

		// OpenIDConnect
		r.GET("/.well-known/openid-configuration", openIDConnectDiscovery)
	}

	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "page/info", gin.H{
			"title": "无法找到页面",
			"icon":  "rocket",
			"msg":   "页面可能已飞去火星",
		})
	})
	r.NoMethod(func(c *gin.Context) {
		c.HTML(http.StatusForbidden, "page/info", gin.H{
			"title": "发现新大陆",
			"icon":  "paw",
			"msg":   "没有这个请求方式哦",
		})
	})
	r.Run(":8080")
}

func genClientID(uid string) (id string, err error) {
	for i := 0; i < 100; i++ {
		id = uid + "-" + com.RandomString(6)
		if _, err = osinStore.GetClient(id); err == nil {
			continue
		}
		return id, nil
	}
	return "", errors.New("genClientID 重试次数达到限制。")
}
