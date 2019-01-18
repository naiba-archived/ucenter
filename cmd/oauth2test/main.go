package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const htmlIndex = `<html><body>
<a href="/GoogleLogin">Log in with Google</a>
</body></html>
`

var endpotin = oauth2.Endpoint{
	AuthURL:  "http://localhost:8080/oauth2/auth",
	TokenURL: "http://localhost:8080/oauth2/token",
}

var googleOauthConfig = &oauth2.Config{
	ClientID:     "1-2GEwTi",
	ClientSecret: "BthSEHFlRChqhdGk",
	RedirectURL:  "http://localhost:8000/GoogleCallback",
	Scopes:       []string{"openid"},
	Endpoint:     endpotin,
}

const oauthStateString = "random"

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
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Println("Code exchange failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	tok, err := jwt.ParseSigned(token.Extra("id_token").(string))
	if err != nil {
		panic(err)
	}

	cl := jwt.Claims{}
	if err := tok.Claims("4f5wg5l2hKsTeNem_V41fGnJm6gOdrj8ym3rFkEU_wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn_MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR-1DcKJzQBSTAGnpYVaqpsARap-nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7w", &cl); err != nil {
		panic(err)
	}

	err = cl.Validate(jwt.Expected{
		Issuer:  "issuer",
		Subject: "subject",
	})

	if err != nil {
		panic(err)
	}

	log.Println(cl)

	return

	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://localhost:8080/oauth2/info?code="+token.AccessToken, nil)
	res, _ := client.Do(req)
	defer res.Body.Close()
	contents, err := ioutil.ReadAll(res.Body)
	fmt.Fprintf(w, "Content: %s\n", contents)
}
