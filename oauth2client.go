package ucenter

import (
	"encoding/json"

	"github.com/RangelReale/osin"
)

// Oauth2Client Oauth2 客户端
type Oauth2Client struct {
	ID          string
	RedirectURI string
	Secret      string
	Ext         struct {
		Logo string
		Name string
		Desc string
	}
}

// ToOauth2Client 转换为客户端Model
func ToOauth2Client(oc osin.Client) (*Oauth2Client, error) {
	var err error
	c := new(Oauth2Client)
	err = json.Unmarshal([]byte(oc.GetUserData().(string)), &c.Ext)
	c.ID = oc.GetId()
	c.RedirectURI = oc.GetRedirectUri()
	c.Secret = oc.GetSecret()
	return c, err
}

// ToOsinClient 转换为OsinClient
func (c *Oauth2Client) ToOsinClient() (osin.Client, error) {
	bd, err := json.Marshal(c.Ext)
	return &osin.DefaultClient{
		Id:          c.ID,
		Secret:      c.Secret,
		RedirectUri: c.RedirectURI,
		UserData:    bd,
	}, err
}
