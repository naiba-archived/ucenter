package ucenter

import (
	"time"

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

	// AuthUser 通过验证的用户
	AuthUser = "ctx_auth_user"
	// AuthCookieName Web验证用的Cookie名称
	AuthCookieName = "nb_uctoken"
	// AuthCookieExpiretion Web验证用的Cookie过期时间
	AuthCookieExpiretion = time.Hour * 24 * 60
	// DBDSN 数据库连接字符串
	DBDSN = "root@tcp(localhost:3306)/ucenter?parseTime=True&loc=Asia%2FShanghai"
	// Domain 系统域名
	Domain = "localhost"
)

var (
	// RouterSkipAuthorize 不需要认证的路由
	RouterSkipAuthorize = map[string]interface{}{
		"/login":  nil,
		"/signup": nil,
	}
	// DB 数据库实例
	DB *gorm.DB
	// ValidatorTrans 翻译工具
	ValidatorTrans ut.Translator
)

func init() {
	var err error
	DB, err = gorm.Open("mysql", DBDSN)
	if err != nil {
		panic(err)
	}
	// 创建数据表
	DB.AutoMigrate(&User{}, &LoginClient{})
	// 初始化错误翻译
	uni := ut.New(en.New(), cn.New())
	var found bool
	ValidatorTrans, found = uni.GetTranslator("zh_Hans")
	if !found {
		panic("Not found translate")
	}
}
