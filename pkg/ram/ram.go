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
)

// InitRAM 初始化权限
func InitRAM(db *gorm.DB) *casbin.Enforcer {
	a := gormadapter.NewAdapterByDB(db)
	m := model.Model{}
	m.LoadModelFromText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`)
	return casbin.NewEnforcer(m, a)
}
