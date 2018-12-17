package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"

	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	mysql "github.com/felipeweb/osin-mysql"
	"github.com/gin-gonic/gin"
)

func main() {
	db, err := sql.Open("mysql", "root@tcp(127.0.0.1:3306)/ucenter?parseTime=true")
	if err != nil {
		panic(err)
	}

	store := mysql.New(db, "osin_")
	err = store.CreateSchemas()
	if err != nil {
		panic(err)
	}
	sconfig := osin.NewServerConfig()
	sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}
	sconfig.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN, osin.PASSWORD, osin.CLIENT_CREDENTIALS, osin.ASSERTION}
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true
	server := osin.NewServer(sconfig, store)

	r := gin.Default()

	o := r.Group("oauth2")
	{
		// Authorization code endpoint
		o.Any("/auth", func(c *gin.Context) {
			resp := server.NewResponse()
			defer resp.Close()

			if ar := server.HandleAuthorizeRequest(resp, c.Request); ar != nil {
				if !example.HandleLoginPage(ar, c.Writer, c.Request) {
					return
				}
				ar.UserData = struct{ Login string }{Login: "test"}
				ar.Authorized = true
				server.FinishAuthorizeRequest(resp, c.Request, ar)
			}
			if resp.IsError && resp.InternalError != nil {
				fmt.Printf("ERROR: %s\n", resp.InternalError)
			}
			if !resp.IsError {
				resp.Output["custom_parameter"] = 187723
			}
			osin.OutputJSON(resp, c.Writer, c.Request)
		})

		// Access token endpoint
		o.Any("/token", func(c *gin.Context) {
			resp := server.NewResponse()
			defer resp.Close()

			if ar := server.HandleAccessRequest(resp, c.Request); ar != nil {
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
				server.FinishAccessRequest(resp, c.Request, ar)
			}
			if resp.IsError && resp.InternalError != nil {
				fmt.Printf("ERROR: %s\n", resp.InternalError)
			}
			if !resp.IsError {
				resp.Output["custom_parameter"] = 19923
			}
			osin.OutputJSON(resp, c.Writer, c.Request)
		})
	}

	r.Run()
}
