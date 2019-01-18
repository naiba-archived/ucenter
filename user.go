package ucenter

import (
	"fmt"

	"github.com/jinzhu/gorm"
)

const (
	// StatusSuspended 账户已被禁用
	StatusSuspended = -1
)

// User 用户表
type User struct {
	gorm.Model
	Username string `gorm:"type:varchar(20);unique_index;notnull" json:"username,omitempty"`
	Password string `json:"-,omitempty"`
	Avatar   bool   `json:"avatar,omitempty"`
	Bio      string `json:"bio,omitempty"`
	Status   int    `json:"status,omitempty"`

	UserAuthorizeds []UserAuthorized `json:"user_authorizeds,omitempty"`
	Logins          []Login          `json:"logins,omitempty"`
}

// StrID 字符串ID
func (u *User) StrID() string {
	return fmt.Sprintf("%d", u.ID)
}
