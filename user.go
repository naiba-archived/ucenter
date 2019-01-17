package ucenter

import (
	"fmt"

	"github.com/jinzhu/gorm"
)

// User 用户表
type User struct {
	gorm.Model
	Username string `gorm:"type:varchar(36);unique_index" json:"username,omitempty"`
	Password string `json:"-"`
	Avatar   string `json:"avatar,omitempty"`
	Bio      string `json:"bio,omitempty"`

	UserAuthorizeds []UserAuthorized `json:"user_authorizeds,omitempty"`
	Logins          []Login          `json:"logins,omitempty"`
}

// StrID 字符串ID
func (u *User) StrID() string {
	return fmt.Sprintf("%d", u.ID)
}
