package ucenter

import (
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
		"baseinfo": "获取用户基本信息",
		"test":     "测试Scope",
	}
)

func init() {
	var err error
	DB, err = gorm.Open("mysql", DBDSN)
	if err != nil {
		panic(err)
	}
	// 创建数据表
	DB.AutoMigrate(&User{}, &Login{}, &UserAuthorized{})
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

	if DebugAble {
		DB = DB.Debug()
		RAM.EnableLog(true)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
}
