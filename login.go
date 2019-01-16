package ucenter

import (
	"time"
)

// Login 登录的终端
type Login struct {
	UserID    uint
	Name      string
	IP        string
	Token     string `gorm:"primary_key"`
	Expire    time.Time
	CreatedAt time.Time

	User User
}
