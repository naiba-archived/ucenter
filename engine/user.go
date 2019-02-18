package engine

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/naiba/ucenter/pkg/fosite-storage"

	"github.com/jinzhu/gorm"
	"github.com/naiba/com"

	"github.com/gin-gonic/gin"
	"github.com/mssola/user_agent"
	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/naiba/ucenter/pkg/ram"
	"github.com/naiba/ucenter/pkg/recaptcha"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
)

var isImage = regexp.MustCompile(`^.*\.((png)|(jpeg)|(jpg)|(gif))$`)

func index(c *gin.Context) {
	u := c.MustGet(ucenter.AuthUser).(*ucenter.User)
	c.HTML(http.StatusOK, "user/index", nbgin.Data(c, gin.H{
		"user": u,
	}))
}

func userStatus(c *gin.Context) {
	type userStatusForm struct {
		ID     uint `form:"id" binding:"required,numeric,min=1"`
		Status int  `form:"status" bindimg:"required,numeric"`
	}

	var usf userStatusForm
	// 验证用户输入
	err := c.ShouldBind(&usf)
	if usf.Status != 0 && usf.Status != ucenter.StatusSuspended {
		err = errors.New("不支持的状态")
	}
	if err == nil {
		err = ucenter.DB.Model(ucenter.User{}).Where("id = ?", usf.ID).Select("status").Update(map[string]interface{}{"status": usf.Status}).Error
	}
	if err != nil {
		c.AbortWithError(http.StatusForbidden, err)
	}
}

func editProfileHandler(c *gin.Context) {
	type editForm struct {
		Username   string `form:"username" cfn:"用户名" binding:"omitempty,min=1,max=20,alphanum"`
		Bio        string `form:"bio" cfn:"简介" binding:"omitempty,min=1,max=255"`
		Password   string `form:"password" cfn:"密码" binding:"omitempty,min=6,max=32,eqfield=RePassword"`
		RePassword string `form:"repassword" cfn:"确认密码" binding:"omitempty,min=6,max=32"`
	}

	var ef editForm
	var errors = make(map[string]string)
	var num int
	u := c.MustGet(ucenter.AuthUser).(*ucenter.User)

	// 验证用户输入
	if err := c.ShouldBind(&ef); err != nil {
		errors = err.(validator.ValidationErrors).Translate(ucenter.ValidatorTrans)
	} else if ef.Username != u.Username {
		if ucenter.DB.Model(ucenter.User{}).Where("username = ?", ef.Username).Count(&num); num != 0 {
			errors["editProfileForm.用户名"] = "用户名已被使用"
		}
	}

	avatar, err := c.FormFile("avatar")
	var f multipart.File
	if err == nil {
		f, err = avatar.Open()
		if err != nil {
			errors["editProfileForm.头像"] = err.Error()
		} else {
			defer f.Close()
			buff := make([]byte, 512) // why 512 bytes ? see http://golang.org/pkg/net/http/#DetectContentType
			_, err = f.Read(buff)
			if err != nil {
				errors["editProfileForm.头像"] = err.Error()
			} else if !strings.HasPrefix(http.DetectContentType(buff), "image/") {
				errors["editProfileForm.头像"] = "头像不是图片文件"
			}
		}
		if !isImage.MatchString(avatar.Filename) {
			errors["editProfileForm.头像"] = "头像不是图片文件"
		} else if avatar.Size > 1024*1024*2 {
			errors["editProfileForm.头像"] = "头像不能大于 2 M"
		}
	}

	if len(errors) > 0 {
		c.JSON(http.StatusForbidden, errors)
		return
	}

	if len(ef.Username) > 0 {
		u.Username = ef.Username
	}
	if len(ef.Bio) > 0 {
		u.Bio = ef.Bio
	}
	if len(ef.RePassword) > 0 {
		bPass, err := bcrypt.GenerateFromPassword([]byte(ef.Password), bcrypt.DefaultCost)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		u.Password = string(bPass)
	}
	if f != nil {
		f.Seek(0, 0)
		out, err := os.Create("data/upload/avatar/" + u.StrID())
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		defer out.Close()
		io.Copy(out, f)
		u.Avatar = true
	}
	if err := ucenter.DB.Save(&u).Error; err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func userDelete(c *gin.Context) {
	id := c.Param("id")
	u := c.MustGet(ucenter.AuthUser).(*ucenter.User)
	if u.StrID() != id && !ucenter.RAM.Enforce(u.StrID(), ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel) {
		c.HTML(http.StatusForbidden, "page/info", gin.H{
			"icon":  "low vision",
			"title": "权限不足",
			"msg":   "您的权限不足以访问此页面哟",
		})
		return
	}

	ucenter.DB.Delete(ucenter.Login{}, "user_id = ?", id)
	ucenter.DB.Delete(ucenter.UserAuthorized{}, "user_id = ?", id)
	ucenter.DB.Delete(storage.FositeClient{}, "owner = ?", id)
	ucenter.DB.Unscoped().Delete(ucenter.User{}, "id = ?", id)
}

func login(c *gin.Context) {
	// 如果已登录，就跳转
	if _, ok := c.Get(ucenter.AuthUser); ok {
		nbgin.SetNoCache(c)
		if returnURL := c.Query("return_url"); strings.HasPrefix(returnURL, "/") {
			c.Redirect(http.StatusFound, returnURL)
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	c.HTML(http.StatusOK, "page/login", nbgin.Data(c, gin.H{}))
}

func logout(c *gin.Context) {
	token, err := c.Cookie(ucenter.C.AuthCookieName)
	if err == nil {
		ucenter.DB.Unscoped().Delete(ucenter.Login{}, "token = ?", token)
	}
	nbgin.SetCookie(c, -1, ucenter.C.AuthCookieName, "")
	nbgin.SetNoCache(c)
	if returnURL := c.Query("return_url"); strings.HasPrefix(returnURL, "/") {
		c.Redirect(http.StatusFound, returnURL)
	} else {
		c.Redirect(http.StatusFound, "/login")
	}
}

func loginHandler(c *gin.Context) {
	// 如果已登录，就停止handler
	if _, ok := c.Get(ucenter.AuthUser); ok {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	type loginForm struct {
		ReCaptcha string `form:"g-recaptcha-response" cfn:"人机验证" binding:"required,min=10"`
		Username  string `form:"username" cfn:"用户名" binding:"required,min=1,max=20"`
		Password  string `form:"password" cfn:"密码" binding:"required,min=6,max=32"`
	}
	var lf loginForm
	var u ucenter.User
	var errors validator.ValidationErrorsTranslations

	// 验证用户输入
	if err := c.ShouldBind(&lf); err != nil {
		errors = err.(validator.ValidationErrors).Translate(ucenter.ValidatorTrans)
	} else if err = ucenter.DB.Where("username = ?", lf.Username).First(&u).Error; err != nil {
		errors = map[string]string{
			"loginForm.用户名": "用户不存在",
		}
	} else if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(lf.Password)) != nil {
		errors = map[string]string{
			"loginForm.密码": "密码不正确",
		}
	} else if ok, _ := recaptcha.Verify(ucenter.C.ReCaptchaSecret, lf.ReCaptcha, c.ClientIP()); !ok {
		errors = map[string]string{
			"loginForm.人机验证": "人机验证未通过",
		}
	}

	if errors != nil {
		c.HTML(http.StatusOK, "page/login", nbgin.Data(c, gin.H{
			"errors": errors,
		}))
		return
	}

	rawUA := c.Request.UserAgent()
	ua := user_agent.New(rawUA)
	var loginClient ucenter.Login
	loginClient.UserID = u.ID
	loginClient.Token = com.MD5(rawUA + time.Now().String() + u.Username)
	browser, _ := ua.Browser()
	loginClient.Name = ua.OS() + " " + browser
	loginClient.IP = c.ClientIP()
	loginClient.Expire = time.Now().Add(ucenter.AuthCookieExpiretion)
	if err := ucenter.DB.Save(&loginClient).Error; err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	nbgin.SetCookie(c, 60*60*24*365*2, ucenter.C.AuthCookieName, loginClient.Token)
	nbgin.SetNoCache(c)
	if returnURL := c.Query("return_url"); strings.HasPrefix(returnURL, "/") {
		c.Redirect(http.StatusFound, returnURL)
	} else {
		c.Redirect(http.StatusFound, "/")
	}
}

func signup(c *gin.Context) {
	// 如果已登录，就跳转
	if _, ok := c.Get(ucenter.AuthUser); ok {
		nbgin.SetNoCache(c)
		if returnURL := c.Query("return_url"); strings.HasPrefix(returnURL, "/") {
			c.Redirect(http.StatusFound, returnURL)
		} else {
			c.Redirect(http.StatusFound, "/")
		}
		return
	}

	c.HTML(http.StatusOK, "page/signup", nbgin.Data(c, gin.H{}))
}

func signupHandler(c *gin.Context) {
	// 如果已登录，就停止handler
	if _, ok := c.Get(ucenter.AuthUser); ok {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	type signUpForm struct {
		ReCaptcha  string `form:"g-recaptcha-response" cfn:"人机验证" binding:"required,min=10"`
		Username   string `form:"username" cfn:"用户名" binding:"required,min=1,max=20,alphanum"`
		Password   string `form:"password" cfn:"密码" binding:"required,min=6,max=32,eqfield=Password"`
		RePassword string `form:"repassword" cfn:"确认密码" binding:"required,min=6,max=32"`
	}
	var suf signUpForm
	var u ucenter.User
	var errors validator.ValidationErrorsTranslations
	if err := c.ShouldBind(&suf); err != nil {
		errors = err.(validator.ValidationErrors).Translate(ucenter.ValidatorTrans)
	} else if err = ucenter.DB.Where("username = ?", suf.Username).First(&u).Error; err != gorm.ErrRecordNotFound {
		errors = map[string]string{
			"signUpForm.用户名": "用户名已存在",
		}
	} else if ok, _ := recaptcha.Verify(ucenter.C.ReCaptchaSecret, suf.ReCaptcha, c.ClientIP()); !ok {
		errors = map[string]string{
			"signUpForm.人机验证": "人机验证未通过",
		}
	}
	if errors != nil {
		c.HTML(http.StatusOK, "page/signup", nbgin.Data(c, gin.H{
			"errors": errors,
		}))
		return
	}
	u.Username = suf.Username
	bPass, err := bcrypt.GenerateFromPassword([]byte(suf.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	u.Password = string(bPass)
	if err := ucenter.DB.Create(&u).Error; err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	// 第一位用户授予 Root 权限
	if u.ID == 1 {
		ucenter.RAM.AddRoleForUserInDomain(u.StrID(), ram.RoleSuperAdmin, ram.DefaultDomain)
	}
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Redirect(http.StatusFound, "/login?"+c.Request.URL.RawQuery)
}

func editOauth2App(c *gin.Context) {
	type Oauth2AppForm struct {
		ID          string `form:"id" cfn:"ID" binding:"omitempty,min=3,max=255"`
		Name        string `form:"name" cfn:"应用名" binding:"required,min=1,max=20"`
		URL         string `form:"url" cfn:"首页链接" binding:"required,url,min=11,max=100"`
		RedirectURI string `form:"redirect_uri" cfn:"跳转链接" binding:"required,url,min=1,max=255"`
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

	var client *storage.FositeClient

	// 验证管理权
	if len(ef.ID) > 0 {
		x, err := oauth2store.GetClient(nil, ef.ID)
		client = x.(*storage.FositeClient)
		isAdmin := ucenter.RAM.Enforce(u.StrID(), ram.DefaultDomain, ram.DefaultProject, ram.PolicyAdminPanel)
		if err != nil || (!strings.HasPrefix(ef.ID, u.StrID()+"-") && !isAdmin) {
			errors["editOauthAppForm.应用名"] = "ID错误"
		}
		if client.Status == storage.StatusOauthClientSuspended && !isAdmin {
			errors["editOauthAppForm.应用名"] = "应用已被禁用，无法进行操作"
		}
	} else {
		client.ClientID, err = genClientID(u.StrID())
		if err != nil {
			errors["editOauthAppForm.应用名"] = "生成应用ID"
		} else {
			client.Secret = com.RandomString(16)
		}
	}

	// 储存头像
	if len(errors) == 0 && f != nil {
		f.Seek(0, 0)
		out, err := os.Create("data/upload/avatar/" + client.ClientID)
		if err != nil {
			errors["editOauthAppForm.应用名"] = "服务器错误，头像储存"
		} else {
			defer out.Close()
			io.Copy(out, f)
		}
		client.LogoURI = "/upload/avatar/" + client.ClientID
	}

	// 应用入库
	if len(errors) == 0 {
		client.Name = ef.Name
		client.ClientURI = ef.URL
		client.RedirectURIs = []string{ef.RedirectURI}
		if ucenter.DB.Save(&client).Error != nil {
			errors["editOauthAppForm.应用名"] = "存入数据库出错"
		}
	}

	if len(errors) > 0 {
		c.JSON(http.StatusForbidden, errors)
		return
	}
}

func deleteOauth2App(c *gin.Context) {
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
	ucenter.DB.Delete(storage.FositeClient{}, "client_id = ?", id)
}
