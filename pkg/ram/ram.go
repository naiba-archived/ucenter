package ram

import (
	"github.com/casbin/casbin"
	"github.com/casbin/casbin/model"
	gormadapter "github.com/casbin/gorm-adapter"
	"github.com/jinzhu/gorm"
)

const (
	// RoleSuperAdmin 超级管理员
	RoleSuperAdmin = "root"
	// PolicyAdminPanel 管理面板权限
	PolicyAdminPanel = "pAdminPanel"
	// DefaultDomain 默认域
	DefaultDomain = "defaultDomain"
	// DefaultProject 默认项目
	DefaultProject = "defaultProject"
)

// InitRAM 初始化权限
func InitRAM(db *gorm.DB) *casbin.Enforcer {
	a := gormadapter.NewAdapterByDB(db)
	m := model.Model{}
	m.LoadModelFromText(`
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _,

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`)
	return casbin.NewEnforcer(m, a)
}

// InitSuperAdminPermission 初始化超级管理员权限
func InitSuperAdminPermission(m *casbin.Enforcer) {
	m.AddPolicy(RoleSuperAdmin, DefaultDomain, DefaultProject, PolicyAdminPanel)
}
