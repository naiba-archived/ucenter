package ucenter

import (
	"encoding/json"

	"github.com/RangelReale/osin"
)

const (
	// StatusOauthClientSuspended 禁用应用
	StatusOauthClientSuspended = -1
)

// Oauth2Client Oauth2 客户端
type Oauth2Client struct {
	ID          string
	RedirectURI string
	Secret      string
	Ext         struct {
		Name   string `json:"name,omitempty"`
		Desc   string `json:"desc,omitempty"`
		Status int    `json:"status,omitempty"`
		URL    string `json:"url,omitempty"`
	}
}

// OsinClient Osin Origin
type OsinClient struct {
	ID          string
	RedirectURI string
	Secret      string
	Extra       string
}

// TableName 自定义表名
func (c OsinClient) TableName() string {
	return "osin_client"
}

// ToOauth2Client 转换为自定义model
func (c OsinClient) ToOauth2Client() (Oauth2Client, error) {
	var err error
	var oc Oauth2Client
	err = json.Unmarshal([]byte(c.Extra), &oc.Ext)
	oc.ID = c.ID
	oc.RedirectURI = c.RedirectURI
	oc.Secret = c.Secret
	return oc, err
}

// ToOsinClient 转换为OsinClient
func (c Oauth2Client) ToOsinClient() (osin.Client, error) {
	bd, err := json.Marshal(c.Ext)
	return &osin.DefaultClient{
		Id:          c.ID,
		Secret:      c.Secret,
		RedirectUri: c.RedirectURI,
		UserData:    bd,
	}, err
}

// ToOauth2Client 转换为客户端Model
func ToOauth2Client(oc osin.Client) (Oauth2Client, error) {
	var err error
	var c Oauth2Client
	err = json.Unmarshal([]byte(oc.GetUserData().(string)), &c.Ext)
	c.ID = oc.GetId()
	c.RedirectURI = oc.GetRedirectUri()
	c.Secret = oc.GetSecret()
	return c, err
}
