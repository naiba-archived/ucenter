package ucenter

import (
	"encoding/json"
	"time"
)

// UserAuthorized 用户已授权的应用
type UserAuthorized struct {
	UserID        uint   `gorm:"index"`
	ClientID      string `gorm:"index"`
	Scope         string
	PermissionRaw string
	Permission    map[string]bool `gorm:"-"`
	CreatedAt     time.Time
	UpdatedAt     time.Time

	User User
}

// DecodePermission 解码用户授权
func (ua *UserAuthorized) DecodePermission() {
	json.Unmarshal([]byte(ua.PermissionRaw), &ua.Permission)
}

// EncodePermission 编码用户授权
func (ua *UserAuthorized) EncodePermission() {
	b, _ := json.Marshal(ua.Permission)
	ua.PermissionRaw = string(b)
}
