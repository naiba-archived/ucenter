package ucenter

import (
	"time"

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
)

var (
	// RouterSkipAuthorize 不需要认证的路由
	RouterSkipAuthorize = map[string]interface{}{
		"x": nil,
	}
	// DB 数据库实例
	DB *gorm.DB
)

func init() {
	var err error
	DB, err = gorm.Open("mysql", DBDSN)
	if err != nil {
		panic(err)
	}
}
