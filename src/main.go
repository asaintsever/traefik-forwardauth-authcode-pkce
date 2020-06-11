package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"

	oidc "github.com/coreos/go-oidc"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
)

var (
	store = sessions.NewCookieStore([]byte("something-very-secret"))
)

type authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

func newAuthenticator() (*authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, os.Getenv("OIDC_PROVIDER_URL"))
	if err != nil {
		log.Printf("failed to get provider: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID: os.Getenv("TRAEFIK_APP_CLIENT_ID"),
		//ClientSecret: we are using Authorization Code with PKCE flow, client secret is not required as long your client is a public application (SPA for eg)
		RedirectURL: os.Getenv("AUTH_CALLBACK_URL"),
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &authenticator{
		Provider: provider,
		Config:   conf,
		Ctx:      ctx,
	}, nil
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Check if we have an error trying to authorize the app (error will be forwarded to our callback: see https://openid.net/specs/openid-connect-core-1_0.html#AuthError)
		if r.URL.Query().Get("error") != "" {
			errorMsg := r.URL.Query().Get("error") + " (" + r.URL.Query().Get("error_description") + ")"
			log.Printf("Error: %s", errorMsg)
			http.Error(w, errorMsg, http.StatusBadRequest)
			return
		}

		session, _ := store.Get(r, "traefik-forwardauth-authcode-pkce-session")

		if r.URL.Query().Get("state") != session.Values["state"].(string) {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		authenticator, err := newAuthenticator()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Provide authorization code and PKCE verifier code to get Access and ID Tokens
		token, err := authenticator.Config.Exchange(context.TODO(), r.URL.Query().Get("code"), oauth2.SetAuthURLParam("code_verifier", session.Values["pkceCodeVerifier"].(string)))
		if err != nil {
			log.Printf("no token found: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}

		oidcConfig := &oidc.Config{
			ClientID: authenticator.Config.ClientID,
		}

		idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Getting the userInfo
		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("== ID Token: %+v", rawIDToken)
		log.Printf("== Access Token: %+v", token.AccessToken)
		log.Printf("== Profile: %+v", profile)

		// Update session max age using ID Token TTL so that session expires when ID Token is no longer valid
		session.Options.MaxAge = int(idToken.Expiry.Sub(idToken.IssuedAt).Seconds())
		session.Values["id_token"] = rawIDToken
		if err = session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to application
		http.Redirect(w, r, os.Getenv("APP_URL"), http.StatusSeeOther)
	})

	// As routes are evaluated in order, this route serves as the default for all other requests
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "traefik-forwardauth-authcode-pkce-session")

		// If session exists then user already authenticated: returns 200
		if !session.IsNew {
			idToken, ok := session.Values["id_token"].(string)
			if ok && idToken != "" {
				log.Printf("User already authenticated")
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		// Generate random state
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		state := base64.StdEncoding.EncodeToString(b)

		authenticator, err := newAuthenticator()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// PKCE: generate code and verifier
		var codeVerifier, _ = pkce.CreateCodeVerifier()
		pkceCodeVerifier := codeVerifier.String()

		// Set PKCE options
		var options []oauth2.AuthCodeOption
		options = append(options, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		options = append(options, oauth2.SetAuthURLParam("code_challenge", codeVerifier.CodeChallengeS256()))

		url := authenticator.Config.AuthCodeURL(state, options...)
		log.Printf("==== New authentication request to OIDC provider")
		log.Printf("Authorize URL: %v", url)

		session.Values["state"] = state
		session.Values["pkceCodeVerifier"] = pkceCodeVerifier
		if err = session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	http.Handle("/", router)
	fmt.Println("Listening on 0.0.0.0:3000")
	http.ListenAndServe("0.0.0.0:3000", router)
}
