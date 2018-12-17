package engine

import (
	"fmt"
	"net/http"

	"git.cm/naiba/ucenter"

	"github.com/RangelReale/osin"
	"github.com/gin-gonic/gin"
)

func oauth2auth(c *gin.Context) {
	resp := OsinServer.NewResponse()
	defer resp.Close()

	if ar := OsinServer.HandleAuthorizeRequest(resp, c.Request); ar != nil {
		user := c.MustGet(ucenter.AuthUser)
		if user != nil {
			ar.UserData = user
			ar.Authorized = true
			OsinServer.FinishAuthorizeRequest(resp, c.Request, ar)
		} else {
			c.String(http.StatusOK, "需要登录")
			return
		}
	}

	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 187723
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
