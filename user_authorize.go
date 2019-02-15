package ucenter

import (
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

// UserAuthorized 用户已授权的应用
type UserAuthorized struct {
	UserID        uint   `gorm:"index"`
	ClientID      string `gorm:"index"`
	Scope         pq.StringArray
	PermissionRaw string
	Permission    map[string]bool `gorm:"-"`
	CreatedAt     time.Time
	UpdatedAt     time.Time

	User User
}

// AfterFind 解码用户授权
func (ua *UserAuthorized) AfterFind() error {
	json.Unmarshal([]byte(ua.PermissionRaw), &ua.Permission)
	return nil
}

// BeforeSave 编码用户授权
func (ua *UserAuthorized) BeforeSave() error {
	b, _ := json.Marshal(ua.Permission)
	ua.PermissionRaw = string(b)
	return nil
}

// BeforeUpdate 编码用户授权
func (ua *UserAuthorized) BeforeUpdate() error {
	b, _ := json.Marshal(ua.Permission)
	ua.PermissionRaw = string(b)
	return nil
}
