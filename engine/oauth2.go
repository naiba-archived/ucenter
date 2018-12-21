package engine

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"git.cm/naiba/ucenter"

	"github.com/RangelReale/osin"
	"github.com/gin-gonic/gin"
)

func oauth2info(c *gin.Context) {
	resp := OsinServer.NewResponse()
	defer resp.Close()

	if ir := OsinServer.HandleInfoRequest(resp, c.Request); ir != nil {
		OsinServer.FinishInfoRequest(resp, c.Request, ir)
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}

func oauth2auth(c *gin.Context) {
	resp := OsinServer.NewResponse()
	defer resp.Close()

	if ar := OsinServer.HandleAuthorizeRequest(resp, c.Request); ar != nil {
		user := c.MustGet(ucenter.AuthUser).(*ucenter.User)
		if user != nil {
			scopes := strings.Split(ar.Scope, ",")
			ucenter.DB.Model(user).Where("client_id = ?", ar.Client.GetId()).Association("UserAuthorizeds").Find(&user.UserAuthorizeds)
			if c.Request.Method == http.MethodGet {
				if len(user.UserAuthorizeds) == 1 && ar.Scope == user.UserAuthorizeds[0].Scope {
					// 用户已经授予权限
					ar.UserData = user.DataDesensitization()
					ar.Authorized = true
					OsinServer.FinishAuthorizeRequest(resp, c.Request, ar)
				} else {
					// 需要用户授予权限
					if len(user.UserAuthorizeds) == 1 {
						user.UserAuthorizeds[0].DecodeScope()
					}
					oc, _ := ucenter.ParseClient(ar.Client)
					var checkPerms = make(map[string]bool)
					for _, scope := range scopes {
						// 判断scope合法性
						if _, has := ucenter.Scopes[scope]; !has {
							resp.SetError(osin.E_INVALID_SCOPE, "不支持的Scope。")
							break
						}
						if len(user.UserAuthorizeds) == 1 {
							checkPerms[scope] = user.UserAuthorizeds[0].ScopePermX[scope]
						} else {
							checkPerms[scope] = true
						}
					}

					// 权限授予界面
					if !resp.IsError {
						c.HTML(http.StatusOK, "page/auth", gin.H{
							"User":   user,
							"Client": oc,
							"Check":  checkPerms,
							"Scopes": ucenter.Scopes,
						})
						return
					}
				}
			} else if c.Request.Method == http.MethodPost {
				// 用户选择了授权的权限
				var perms = make(map[string]bool)
				for _, scope := range scopes {
					if _, has := ucenter.Scopes[scope]; !has {
						resp.SetError(osin.E_INVALID_SCOPE, "不支持的Scope。")
						break
					}
					perms[scope] = c.PostForm(scope) == "on"
				}
				if !resp.IsError {
					var ua ucenter.UserAuthorized
					if len(user.UserAuthorizeds) == 1 {
						ua = user.UserAuthorizeds[0]
					}
					ua.Scope = ar.Scope
					ua.ScopePermX = perms
					ua.UserID = user.ID
					ua.ClientID = ar.Client.GetId()
					ua.EncodeScope()
					// 是新增还是更新
					var err error
					if len(user.UserAuthorizeds) == 0 {
						err = ucenter.DB.Save(&ua).Error
					} else {
						err = ucenter.DB.Model(&ua).Save(ua).Error
					}
					if err != nil {
						resp.SetError(osin.E_SERVER_ERROR, err.Error())
					} else {
						ar.UserData = user.DataDesensitization()
						ar.Authorized = true
						OsinServer.FinishAuthorizeRequest(resp, c.Request, ar)
					}
				}
			} else {
				resp.SetError(osin.E_INVALID_REQUEST, "不支持的请求方式哦。")
			}
		} else {
			// 用户未登录，跳转登录界面
			resp.SetRedirect("/login?from=" + url.QueryEscape(c.Request.RequestURI))
		}
	}

	if resp.IsError && resp.InternalError != nil {
		log.Println("ERROR Oauth2: ", resp.InternalError)
	}

	osin.OutputJSON(resp, c.Writer, c.Request)
}

func oauth2token(c *gin.Context) {
	resp := OsinServer.NewResponse()
	defer resp.Close()

	if ar := OsinServer.HandleAccessRequest(resp, c.Request); ar != nil {
		switch ar.Type {
		case osin.AUTHORIZATION_CODE:
			ar.Authorized = true
		case osin.REFRESH_TOKEN:
			ar.Authorized = true
		case osin.PASSWORD:
			if ar.Username == "test" && ar.Password == "test" {
				ar.Authorized = true
			}
		case osin.CLIENT_CREDENTIALS:
			ar.Authorized = true
		case osin.ASSERTION:
			if ar.AssertionType == "urn:nb.unknown" && ar.Assertion == "very.newbie" {
				ar.Authorized = true
			}
		}
		OsinServer.FinishAccessRequest(resp, c.Request, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 19923
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}
