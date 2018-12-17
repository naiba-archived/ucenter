package ucenter

import (
	"time"

	"github.com/jinzhu/gorm"
)

// LoginClient 登录的终端
type LoginClient struct {
	gorm.Model
	User   User
	UserID uint
	Name   string
	IP     string
	Token  string
	Expire time.Time
}
