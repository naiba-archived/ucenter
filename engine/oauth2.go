package engine

import (
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/naiba/com"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/naiba/ucenter/pkg/ram"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/naiba/ucenter"

	"github.com/RangelReale/osin"
	"github.com/gin-gonic/gin"
)

func oauth2info(c *gin.Context) {
	resp := osinServer.NewResponse()
	defer resp.Close()

	if ir := osinServer.HandleInfoRequest(resp, c.Request); ir != nil {
		osinServer.FinishInfoRequest(resp, c.Request, ir)
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}

func oauth2auth(c *gin.Context) {
	resp := osinServer.NewResponse()
	defer resp.Close()

	if ar := osinServer.HandleAuthorizeRequest(resp, c.Request); ar != nil {
		user, ok := c.Get(ucenter.AuthUser)
		if ok {
			user := user.(*ucenter.User)
			scopes := strings.Split(ar.Scope, ",")
			ucenter.DB.Model(user).Where("client_id = ?", ar.Client.GetId()).Association("UserAuthorizeds").Find(&user.UserAuthorizeds)
			if c.Request.Method == http.MethodGet {
				if len(user.UserAuthorizeds) == 1 && ar.Scope == user.UserAuthorizeds[0].Scope {
					// 用户已经授予权限
					ar.UserData = user
					ar.Authorized = true
					osinServer.FinishAuthorizeRequest(resp, c.Request, ar)
				} else {
					// 需要用户授予权限
					if len(user.UserAuthorizeds) == 1 {
						user.UserAuthorizeds[0].DecodePermission()
					}
					oc, _ := ucenter.ToOauth2Client(ar.Client)
					var checkPerms = make(map[string]bool)
					for _, scope := range scopes {
						// 判断scope合法性
						if _, has := ucenter.Scopes[scope]; !has {
							resp.SetError(osin.E_INVALID_SCOPE, "不支持的Scope。")
							break
						}
						if len(user.UserAuthorizeds) == 1 {
							checkPerms[scope] = user.UserAuthorizeds[0].Permission[scope]
						} else {
							checkPerms[scope] = true
						}
					}

					// 权限授予界面
					if !resp.IsError {
						c.HTML(http.StatusOK, "page/auth", nbgin.Data(c, gin.H{
							"User":   user,
							"Client": oc,
							"Check":  checkPerms,
							"Scopes": ucenter.Scopes,
						}))
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
					ua.Permission = perms
					ua.UserID = user.ID
					ua.ClientID = ar.Client.GetId()
					ua.EncodePermission()
					// 新增授权还是更新授权
					var err error
					if len(user.UserAuthorizeds) == 0 {
						err = ucenter.DB.Save(&ua).Error
					} else {
						err = ucenter.DB.Model(&ua).Save(ua).Error
					}
					if err != nil {
						resp.SetError(osin.E_SERVER_ERROR, err.Error())
					} else {
						// 认证通过标识
						ar.Authorized = true
						// 如果是 OpenIDConnect，特殊照顾
						if perms["openid"] {
							now := time.Now()
							idToken := IDToken{
								Issuer:     "http://localhost:8080",
								UserID:     user.StrID(),
								ClientID:   ar.Client.GetId(),
								Expiration: now.Add(time.Hour).Unix(),
								IssuedAt:   now.Unix(),
								Nonce:      c.Request.URL.Query().Get("nonce"),
							}

							if perms["profile"] {
								idToken.Name = user.Username
								idToken.GivenName = user.Username
								idToken.FamilyName = ""
								idToken.Locale = "zh-CN"
							}

							if perms["email"] {
								t := true
								idToken.Email = ""
								idToken.EmailVerified = &t
							}
							ar.UserData = &idToken
						} else {
							ar.UserData = user
						}
						osinServer.FinishAuthorizeRequest(resp, c.Request, ar)
					}
				}
			} else {
				resp.SetError(osin.E_INVALID_REQUEST, "不支持的请求方式哦。")
			}
		} else {
			// 用户未登录，跳转登录界面
			resp.SetRedirect("/login?return_url=" + url.QueryEscape(c.Request.RequestURI))
		}
	}

	if resp.IsError && resp.InternalError != nil {
		log.Println("ERROR Oauth2: ", resp.InternalError)
	}

	osin.OutputJSON(resp, c.Writer, c.Request)
}

func oauth2token(c *gin.Context) {
	resp := osinServer.NewResponse()
	defer resp.Close()

	if ar := osinServer.HandleAccessRequest(resp, c.Request); ar != nil {
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
		osinServer.FinishAccessRequest(resp, c.Request, ar)

		// If an ID Token was encoded as the UserData, serialize and sign it.
		if idToken, ok := ar.UserData.(*IDToken); ok && idToken != nil {
			encodeIDToken(resp, idToken, jwtSigner)
		}
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 19923
	}
	osin.OutputJSON(resp, c.Writer, c.Request)
}

func editOauth2App(c *gin.Context) {
	type Oauth2AppForm struct {
		ID          string `form:"id" cfn:"ID" binding:"omitempty,min=3,max=255"`
		Name        string `form:"name" cfn:"应用名" binding:"required,min=1,max=255"`
		Desc        string `form:"desc" cfn:"简介" binding:"required,min=1,max=255"`
		RedirectURI string `form:"redirect_uri" cfn:"跳转链接" binding:"required,min=1,max=255"`
	}

	var ef Oauth2AppForm
	var errors = make(map[string]string)
	u := c.MustGet(ucenter.AuthUser).(*ucenter.User)

	// 验证用户输入
	if err := c.ShouldBind(&ef); err != nil {
		errors = err.(validator.ValidationErrors).Translate(ucenter.ValidatorTrans)
	}

	// 验证头像是否是图片文件
	avatar, err := c.FormFile("avatar")
	var f multipart.File
	if err == nil {
		f, err = avatar.Open()
		if err != nil {
			errors["editOauthAppForm.应用名"] = err.Error()
		} else {
			defer f.Close()
			buff := make([]byte, 512) // why 512 bytes ? see http://golang.org/pkg/net/http/#DetectContentType
			_, err = f.Read(buff)
			if err != nil {
				errors["editOauthAppForm.应用名"] = err.Error()
			} else if !strings.HasPrefix(http.DetectContentType(buff), "image/") {
				errors["editOauthAppForm.应用名"] = "头像不是图片文件"
			}
		}
		if !isImage.MatchString(avatar.Filename) {
			errors["editOauthAppForm.应用名"] = "头像不是图片文件"
		} else if avatar.Size > 1024*1024*2 {
			errors["editOauthAppForm.应用名"] = "头像不能大于 2 M"
		}
	} else if ef.ID == "" {
		errors["editOauthAppForm.圆图标"] = "圆图标必须上传"
	}

	var client ucenter.Oauth2Client
	isNewClient := false

	// 验证管理权
	if len(ef.ID) > 0 {
		oc, err := osinStore.GetClient(ef.ID)
		if err != nil || (!strings.HasPrefix(ef.ID, u.StrID()+"-") && ucenter.RAM.Enforce(u.StrID(), ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel)) {
			log.Println(err, strings.HasPrefix(ef.ID, u.StrID()+"-"), ucenter.RAM.Enforce(u.StrID(), ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel))
			errors["editOauthAppForm.应用名"] = "ID错误"
		} else {
			client, err = ucenter.ToOauth2Client(oc)
			if err != nil {
				errors["editOauthAppForm.应用名"] = "服务器错误，解析JSON"
			}
		}
	} else {
		isNewClient = true
		client.ID, err = genClientID(u.StrID())
		if err != nil {
			errors["editOauthAppForm.应用名"] = "服务器错误，解析JSON"
		} else {
			client.Secret = com.RandomString(16)
		}
	}

	// 储存头像
	if len(errors) == 0 && f != nil {
		f.Seek(0, 0)
		out, err := os.Create("upload/avatar/" + client.ID)
		if err != nil {
			errors["editOauthAppForm.应用名"] = "服务器错误，头像储存"
		} else {
			defer out.Close()
			io.Copy(out, f)
		}
	}

	// 应用入库
	if len(errors) == 0 {
		var oc osin.Client
		client.Ext.Name = ef.Name
		client.Ext.Desc = ef.Desc
		client.RedirectURI = ef.RedirectURI
		oc, err = client.ToOsinClient()
		if isNewClient {
			err = osinStore.CreateClient(oc)
		} else {
			err = osinStore.UpdateClient(oc)
		}
		if err != nil {
			errors["editOauthAppForm.应用名"] = "存入数据库出错"
		}
	}

	if len(errors) > 0 {
		c.JSON(http.StatusForbidden, errors)
		return
	}
}

func deleteOauth2App(c *gin.Context) {
	if !strings.Contains(c.Request.Referer(), "://"+ucenter.Domain) {
		c.String(http.StatusForbidden, "CSRF Protection")
		return
	}

	id := c.Param("id")
	u := c.MustGet(ucenter.AuthUser).(*ucenter.User)
	if strings.HasPrefix(id, u.StrID()+"-") && !ucenter.RAM.Enforce(u.StrID(), ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel) {
		c.HTML(http.StatusForbidden, "page/info", gin.H{
			"icon":  "low vision",
			"title": "权限不足",
			"msg":   "您的权限不足以访问此页面哟",
		})
		return
	}

	ucenter.DB.Delete(ucenter.UserAuthorized{}, "client_id = ?", id)
	ucenter.DB.Delete(ucenter.OsinClient{}, "id = ?", id)
}
