package ucenter

import (
	"time"

	"github.com/jinzhu/gorm"
)

// Login 登录的终端
type Login struct {
	gorm.Model
	UserID uint
	Name   string
	IP     string
	Token  string
	Expire time.Time

	User User
}
