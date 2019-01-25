package ucenter

// Config 配置文件
type Config struct {
	AuthCookieName  string `mapstructure:"auth_cookie_name"` //Web验证用的Cookie名称
	ReCaptchaSecret string `mapstructure:"recaptcha_secret"` //ReCaptcha密钥
	DBDSN           string `mapstructure:"dbdsn"`            //Mysql链接字符串 "root@tcp(localhost:3306)/ucenter?parseTime=True&loc=Asia%2FShanghai"
	Domain          string //系统域名
	DebugAble       bool   `mapstructure:"debug"`        //开启调试
	SysName         string `mapstructure:"sysname"`      //系统名称
	PrivateKeyByte  string `mapstructure:"privatekey"`   //系统私钥
	WebProtocol     string `mapstructure:"web_protocol"` //http or https
}
