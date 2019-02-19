package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const htmlIndex = `<html><body>
<a href="/GoogleLogin">Log in with Google</a>
</body></html>
`

// IDToken 4 OpenIDConnect
type IDToken struct {
	Issuer     string `json:"iss"`
	UserID     string `json:"sub"`
	ClientID   string `json:"aud"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`

	Nonce string `json:"nonce,omitempty"` // Non-manditory fields MUST be "omitempty"

	// Custom claims supported by this server.
	// See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	Avatar string `json:"avatar,omitempty"`
	Name   string `json:"name,omitempty"`
}

var endpotin = oauth2.Endpoint{
	AuthURL:  "http://localhost:8080/oauth2/auth",
	TokenURL: "http://localhost:8080/oauth2/token",
}

var googleOauthConfig = &oauth2.Config{
	ClientID:     "1-Ka9OvC",
	ClientSecret: ".Vdv7PluoCxxyyvSU.O135grMef9uw8eJITRJLn.N87YbdRk.",
	RedirectURL:  "http://localhost:8000/GoogleCallback",
	Scopes:       []string{"profile openid"},
	Endpoint:     endpotin,
}

const oauthStateString = "randomxx"

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/GoogleLogin", handleGoogleLogin)
	http.HandleFunc("/GoogleCallback", handleGoogleCallback)
	fmt.Println(http.ListenAndServe(":8000", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	fmt.Println(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://localhost:8080")
	if err != nil {
		log.Println(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: googleOauthConfig.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Println("exchange err", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// jwt 验证
	cl, err := verifier.Verify(ctx, token.Extra("id_token").(string))
	if err != nil {
		panic(err)
	}
	log.Println("CL", cl)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://localhost:8080/oauth2/info?access_token="+token.AccessToken, nil)
	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()
	contents, err := ioutil.ReadAll(res.Body)
	fmt.Fprintf(w, "Content: %s\n", contents)
}
