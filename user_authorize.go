package ucenter

import (
	"github.com/jinzhu/gorm"
)

// UserAuthorized 用户已授权的应用
type UserAuthorized struct {
	gorm.Model
	UserID    uint
	Scope     string
	ScopePerm string
	ClientID  string

	User User
}
