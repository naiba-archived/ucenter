package engine

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/ory/fosite"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/naiba/com"
	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/fosite-storage"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/naiba/ucenter/pkg/ram"
	"github.com/ory/fosite/compose"
)

var oauth2provider fosite.OAuth2Provider
var oauth2store fosite.Storage

func initFosite() {
	oauth2store = storage.NewFositeStore(ucenter.DB, true)
	oauth2store.(*storage.FositeStore).Migrate()

	var config = new(compose.Config)

	// Because we are using oauth2 and open connect id, we use this little helper to combine the two in one
	// variable.
	var strat = compose.CommonStrategy{
		// alternatively you could use:
		// CoreStrategy: compose.NewOAuth2JWTStrategy(ucenter.SystemRSAKey),
		CoreStrategy: compose.NewOAuth2HMACStrategy(config,
			[]byte("some-super-cool-secret-that-nobody-knows"),
			[][]byte{
				[]byte("some-super-cool-secret-that-nobody-knows")},
		),
		// open id connect strategy
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(config, ucenter.SystemRSAKey),
	}

	oauth2provider = compose.Compose(
		config,
		oauth2store,
		strat,
		nil,

		// enabled handlers
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2ResourceOwnerPasswordCredentialsFactory,

		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,

		// be aware that open id connect factories need to be added after oauth2 factories to work properly.
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,
	)
}

// ServWeb 开启Web服务
func ServWeb() {
	initFosite()
	binding.Validator = new(nbgin.DefaultValidator)
	r := gin.Default()
	r.Static("static", "static")
	r.Static("upload", "data/upload")
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

	// Well-known handler
	r.GET(".well-known/openid-configuration", wellknownHandler)
	r.GET(".well-known/jwks.json", jwksHandler)

	// 鉴权
	r.Use(authorizeMiddleware)

	// CSRF Protection
	r.Use(func(c *gin.Context) {
		if (c.Request.Method == http.MethodDelete ||
			c.MustGet(ucenter.RequestRouter) == "/logout") &&
			!strings.Contains(c.Request.Referer(), "://"+ucenter.C.Domain+"/") {
			c.AbortWithError(http.StatusForbidden, errors.New("CSRF Protection"))
			return
		}
	})

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
		o.GET("auth", oauth2auth)
		o.POST("auth", oauth2auth)
		o.GET("token", oauth2token)
		o.POST("token", oauth2token)
		o.GET("revoke", revokeEndpoint)
		o.POST("revoke", revokeEndpoint)
		o.GET("introspect", introspectionEndpoint)
		o.POST("introspect", introspectionEndpoint)
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
	r.Run("0.0.0.0:8080")
}

func genClientID(uid string) (id string, err error) {
	for i := 0; i < 100; i++ {
		id = uid + "-" + com.RandomString(6)
		if _, err = oauth2store.GetClient(nil, id); err == nil {
			continue
		}
		return id, nil
	}
	return "", errors.New("genClientID 重试次数达到限制。")
}
