package ucenter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/casbin/casbin"
	"github.com/naiba/ucenter/pkg/ram"

	"github.com/go-playground/locales/en"
	cn "github.com/go-playground/locales/zh_Hans"
	ut "github.com/go-playground/universal-translator"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"

	// MySQL Driver
	_ "github.com/jinzhu/gorm/dialects/postgres"
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
	// AuthCookieExpiretion Web验证用的Cookie过期时间
	AuthCookieExpiretion = time.Hour * 24 * 60
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
		"openid":  "获取必要信息(必选)",
		"profile": "获取个人资料(用户名、简介等)",
	}
	// SystemRSAKey 系统RSA私钥
	SystemRSAKey *rsa.PrivateKey
	// C 全站设置
	C *Config
)

func init() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.AddConfigPath("data")   // optionally look for config in the working directory
	err := viper.ReadInConfig()   // Find and read the config file
	if err != nil {               // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}
	err = viper.Unmarshal(&C)
	if err != nil {
		panic(err)
	}

	DB, err = gorm.Open("postgres", C.DBDSN)
	if err != nil {
		panic(err)
	}
	// 创建数据表
	DB.AutoMigrate(&User{}, &Login{}, &UserAuthorized{})
	if C.DebugAble {
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
	block, _ := pem.Decode([]byte(C.PrivateKeyByte))
	if block == nil {
		panic("no private key found")
	}
	SystemRSAKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}
