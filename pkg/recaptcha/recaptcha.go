package recaptcha

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

type recaptchaResp struct {
	Success  bool
	Hostname string
}

//Verify 验证验证码
func Verify(secret, gresp, ip string) (flag bool, host string) {
	if len(gresp) < 10 {
		return false, ""
	}
	resp, err := http.Post("https://www.recaptcha.net/recaptcha/api/siteverify",
		"application/x-www-form-urlencoded",
		strings.NewReader("secret="+secret+"&response="+gresp+"&remoteip="+ip))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var rp recaptchaResp
	err = json.Unmarshal(body, &rp)
	if err != nil {
		return
	}
	return rp.Success, rp.Hostname
}
