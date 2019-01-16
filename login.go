package ucenter

import (
	"time"
)

// Login 登录的终端
type Login struct {
	Token     string `gorm:"primary_key"`
	UserID    uint
	Name      string
	IP        string
	Expire    time.Time
	CreatedAt time.Time

	User User
}
