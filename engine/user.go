package engine

import (
	"net/http"

	"git.cm/naiba/ucenter"
	"github.com/gin-gonic/gin"
	"gopkg.in/go-playground/validator.v9"
)

func login(c *gin.Context) {
	c.HTML(http.StatusOK, "page/login", gin.H{})
}

func loginHandler(c *gin.Context) {
}

func signup(c *gin.Context) {
	c.HTML(http.StatusOK, "page/signup", gin.H{})
}

func signupHandler(c *gin.Context) {
	type signUpForm struct {
		Username   string `form:"username" cfn:"用户名" binding:"required,min=2,max=12"`
		Password   string `form:"password" cfn:"密码" binding:"required,min=6,max=32"`
		RePassword string `form:"repassword" cfn:"确认密码" binding:"required,min=6,max=32,eqfield=Password"`
	}
	var suf signUpForm
	if err := c.ShouldBind(&suf); err != nil {
		c.JSON(http.StatusForbidden, err.(validator.ValidationErrors).Translate(ucenter.ValidatorTrans))
		return
	}
	c.JSON(200, suf)
}
