package ucenter

import (
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
)

// User 用户表
type User struct {
	gorm.Model
	Username string `gorm:"type:varchar(36);unique_index" json:"username,omitempty"`
	Password string `json:"-"`
	Email    string `gorm:"type:varchar(100)" json:"email,omitempty"`
	Phone    string `gorm:"type:varchar(11)" json:"phone,omitempty"`

	UserAuthorizeds []UserAuthorized `json:"-"`
	Logins          []Login          `json:"-"`
}

// DataDesensitization 数据去敏
func (u *User) DataDesensitization() User {
	if len(u.Email) > 0 {
		pubEmail := make([]byte, 0)
		pubEmail = append(pubEmail, u.Email[0])
		pubEmail = append(pubEmail, []byte("****")...)
		pubEmail = append(pubEmail, u.Email[strings.LastIndex(u.Email, "@"):]...)
		u.Email = string(pubEmail)
	}

	if len(u.Phone) > 0 {
		pubPhone := make([]byte, 0)
		pubPhone = append(pubPhone, u.Phone[:4]...)
		pubPhone = append(pubPhone, []byte("****")...)
		pubPhone = append(pubPhone, u.Phone[9:]...)
		u.Phone = string(pubPhone)
	}

	u.UserAuthorizeds = nil
	return *u
}

// StrID 字符串ID
func (u *User) StrID() string {
	return fmt.Sprintf("%d", u.ID)
}
