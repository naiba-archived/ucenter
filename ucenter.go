package ucenter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/casbin/casbin"
	"github.com/naiba/ucenter/pkg/ram"

	"github.com/go-playground/locales/en"
	cn "github.com/go-playground/locales/zh_Hans"
	ut "github.com/go-playground/universal-translator"
	"github.com/jinzhu/gorm"

	// MySQL Driver
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

const (
	// AuthType 授权类型
	AuthType = "ctx_auth_type"
	// AuthTypeCookie 通过Cookie验证
	AuthTypeCookie = "ctx_auth_type_cookie"
	// AuthTypeAccessToken 通过AccessToken验证
	AuthTypeAccessToken = "ctx_auth_type_access_token"
	// RequestRouter 请求的路由路径
	RequestRouter = "ctx_request_router"
	// AuthUser 通过验证的用户
	AuthUser = "ctx_auth_user"
	// AuthCookieName Web验证用的Cookie名称
	AuthCookieName = "nb_uctoken"

	// AuthCookieExpiretion Web验证用的Cookie过期时间
	AuthCookieExpiretion = time.Hour * 24 * 60
	// DBDSN 数据库连接字符串
	DBDSN = "root@tcp(localhost:3306)/ucenter?parseTime=True&loc=Asia%2FShanghai"
	// Domain 系统域名
	Domain = "localhost:8080"

	// DebugAble 允许调试
	DebugAble = true
)

var (
	// RouteNeedAuthorize 需要认证的路由
	RouteNeedAuthorize = map[string]interface{}{
		"/":                  nil,
		"/login":             nil,
		"/signup":            nil,
		"/logout":            nil,
		"/app":               nil,
		"/oauth2/auth":       nil,
		"/app/:id":           nil,
		"/user/:id":          nil,
		"/admin/":            []interface{}{ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel},
		"/admin/users":       []interface{}{ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel},
		"/admin/apps":        []interface{}{ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel},
		"/admin/user/status": []interface{}{ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel},
		"/admin/app/status":  []interface{}{ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel},
	}
	// RouteTitle 页面标题
	RouteTitle = map[string]string{
		"/":            "个人中心",
		"/admin/":      "管理中心",
		"/admin/users": "用户管理",
		"/admin/apps":  "应用管理",
		"/login":       "用户登录",
		"/signup":      "用户注册",
		"/oauth2/auth": "用户授权",
	}
	// RAM 权限系统
	RAM *casbin.Enforcer
	// DB 数据库实例
	DB *gorm.DB
	// ValidatorTrans 翻译工具
	ValidatorTrans ut.Translator
	// Scopes 可以使用的 scope 列表
	Scopes = map[string]string{
		"openid": "获取用户基本信息",
	}
	// 系统RSA私钥
	SystemRSAKey *rsa.PrivateKey
)

func init() {
	var err error
	DB, err = gorm.Open("mysql", DBDSN)
	if err != nil {
		panic(err)
	}
	// 创建数据表
	DB.AutoMigrate(&User{}, &Login{}, &UserAuthorized{})
	if DebugAble {
		DB = DB.Debug()
		RAM.EnableLog(true)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	DB.Raw("ALTER TABLE osin_access MODIFY COLUMN extra VARCHAR(1000);")
	DB.Raw("ALTER TABLE osin_authorize MODIFY COLUMN extra VARCHAR(1000);")
	// 初始化错误翻译
	uni := ut.New(en.New(), cn.New())
	var found bool
	ValidatorTrans, found = uni.GetTranslator("zh_Hans")
	if !found {
		panic("Not found translate")
	}
	// 初始化 RAM
	RAM = ram.InitRAM(DB)
	ram.InitSuperAdminPermission(RAM)
	RAM.EnableAutoSave(true)
	// Load signing key.
	privateKeyBytes := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----`)
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		panic("no private key found")
	}
	SystemRSAKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}
