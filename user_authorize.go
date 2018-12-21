package ucenter

import (
	"encoding/json"

	"github.com/jinzhu/gorm"
)

// UserAuthorized 用户已授权的应用
type UserAuthorized struct {
	gorm.Model
	UserID     uint
	Scope      string
	ScopePerm  string
	ScopePermX map[string]bool `gorm:"-"`
	ClientID   string

	User User
}

// DecodeScope 解码scope
func (ua *UserAuthorized) DecodeScope() {
	json.Unmarshal([]byte(ua.ScopePerm), &ua.ScopePermX)
}

// EncodeScope 编码scope
func (ua *UserAuthorized) EncodeScope() {
	b, _ := json.Marshal(ua.ScopePermX)
	ua.ScopePerm = string(b)
}
