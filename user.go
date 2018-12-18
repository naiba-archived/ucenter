package ucenter

import (
	"strings"

	"github.com/jinzhu/gorm"
)

// User 用户表
type User struct {
	gorm.Model
	Username string `gorm:"type:varchar(36);unique_index"`
	Password string `json:"-"`
	Email    string `gorm:"type:varchar(100)"`
	Phone    string `gorm:"type:varchar(11)"`
}

// DataDesensitization 数据去敏
func (u *User) DataDesensitization() {
	pubEmail := make([]byte, 0)
	pubEmail = append(pubEmail, u.Email[0])
	pubEmail = append(pubEmail, []byte("****")...)
	pubEmail = append(pubEmail, u.Email[strings.LastIndex(u.Email, "@"):]...)
	u.Email = string(pubEmail)

	pubPhone := make([]byte, 0)
	pubPhone = append(pubPhone, u.Phone[0:4]...)
	pubPhone = append(pubPhone, []byte("****")...)
	pubPhone = append(pubPhone, u.Phone[7:11]...)
	u.Phone = string(pubPhone)
}
