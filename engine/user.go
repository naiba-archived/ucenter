package engine

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/naiba/com"

	"github.com/gin-gonic/gin"
	"github.com/mssola/user_agent"
	"github.com/naiba/ucenter"
	"github.com/naiba/ucenter/pkg/nbgin"
	"github.com/naiba/ucenter/pkg/ram"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
)

var isImage = regexp.MustCompile(`^.*\.((png)|(jpeg)|(jpg)|(gif))$`)

func index(c *gin.Context) {
	c.HTML(http.StatusOK, "page/index", nbgin.Data(c, gin.H{}))
}

func editProfile(c *gin.Context) {
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
	if err == nil {
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
	if avatar != nil {
		err = c.SaveUploadedFile(avatar, fmt.Sprintf("upload/avatar/%d", u.ID))
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		u.Avatar = true
	}
	if err := ucenter.DB.Save(&u).Error; err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func login(c *gin.Context) {
	c.HTML(http.StatusOK, "page/login", nbgin.Data(c, gin.H{}))
}

func logout(c *gin.Context) {
	if !strings.Contains(c.Request.Referer(), "://"+ucenter.Domain) {
		c.String(http.StatusForbidden, "CSRF Protection")
		return
	}
	nbgin.SetCookie(c, -1, ucenter.AuthCookieName, "")
	nbgin.SetNoCache(c)
	if returnURL := c.Query("return_url"); strings.HasPrefix(returnURL, "/") {
		c.Redirect(http.StatusFound, returnURL)
	} else {
		c.Redirect(http.StatusTemporaryRedirect, "/login")
	}
}

func loginHandler(c *gin.Context) {
	type loginForm struct {
		Username string `form:"username" cfn:"用户名" binding:"required,min=1,max=20"`
		Password string `form:"password" cfn:"密码" binding:"required,min=6,max=32"`
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
	}

	if errors != nil {
		c.HTML(http.StatusOK, "page/login", nbgin.Data(c, gin.H{
			"errors": map[string]interface{}{
				"Username": errors["loginForm.用户名"],
				"Password": errors["loginForm.密码"],
			},
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
	nbgin.SetCookie(c, 60*60*24*365*2, ucenter.AuthCookieName, loginClient.Token)
	nbgin.SetNoCache(c)
	if returnURL := c.Query("return_url"); strings.HasPrefix(returnURL, "/") {
		c.Redirect(http.StatusFound, returnURL)
		return
	}
	c.String(http.StatusOK, "登录成功")
}

func signup(c *gin.Context) {
	c.HTML(http.StatusOK, "page/signup", nbgin.Data(c, gin.H{}))
}

func signupHandler(c *gin.Context) {
	type signUpForm struct {
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
	}
	if errors != nil {
		c.HTML(http.StatusOK, "page/signup", nbgin.Data(c, gin.H{
			"errors": map[string]interface{}{
				"Username":   errors["signUpForm.用户名"],
				"Password":   errors["signUpForm.密码"],
				"RePassword": errors["signUpForm.确认密码"],
			},
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
		ucenter.RAM.AddRoleForUser(u.StrID(), ram.RoleSuperAdmin)
	}
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Redirect(http.StatusFound, "/login?"+c.Request.URL.RawQuery)
}
