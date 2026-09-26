package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/iveteran/OAuth2ACF/service"
	"golang.org/x/oauth2"
)

type AuthController struct {
	Service    *service.AuthService
	challenges map[string]map[string]string // userId -> challenge -> platform
}

// /authorize?provider=google&user_id=alice[&scheme=myapp&platform=desktop&challenge=xyz&cacheMode=none]
func (c *AuthController) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	userID := r.URL.Query().Get("user_id")
	if provider == "" || userID == "" {
		http.Error(w, "error: miss required parameter", http.StatusBadRequest)
		return
	}

	scheme := r.URL.Query().Get("scheme")
	platform := r.URL.Query().Get("platform")
	challenge := r.URL.Query().Get("challenge")
	if challenge != "" {
		if c.challenges == nil {
			c.challenges = make(map[string]map[string]string)
		}
		if c.challenges[userID] == nil {
			c.challenges[userID] = make(map[string]string)
		}
		c.challenges[userID][challenge] = platform
	}
	cacheMode := r.URL.Query().Get("cacheMode")
	if cacheMode == "" {
		cacheMode = "none"
	}

	url, err := c.Service.GetAuthURL(provider, userID, platform, scheme, cacheMode)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// /callback?state=provider:user_id:platform:scheme:cacheMode&code=xxx
func (c *AuthController) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	parts := strings.SplitN(r.URL.Query().Get("state"), ":", 5)
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	provider, userID, platform, scheme, cacheMode :=
		parts[0], parts[1], parts[2], parts[3], parts[4]

	if strings.EqualFold(cacheMode, "persistence") {
		if err := c.Service.HandleCallback(provider, userID, code); err != nil {
			http.Error(w, "callback error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := c.Service.HandleCallbackWithoutStore(provider, userID, code); err != nil {
			http.Error(w, "callback error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if platform == "ios" || platform == "android" {
		redirect := fmt.Sprintf("%s://auth/callback?provider=%s&user=%s",
			scheme, provider, userID)
		http.Redirect(w, r, redirect, http.StatusFound)
	} else {
		// 桌面应用不支持从浏览器跳回应用
		fmt.Fprintf(w, "<html><h1>%s login successful! You can close this window.</h1></html>", provider)
	}
}

// /get_token?provider=google[&user_id=xxx&challenge=yyy]
func (c *AuthController) GetToken(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}
	userVerified := false
	// 如果用户没有提供JWT，说明App没有(或不支持)通过Deep Link获取到JWT，就用challenge验证用户
	userID := r.URL.Query().Get("user_id")
	challenge := r.URL.Query().Get("challenge")
	if userID != "" && challenge != "" && c.challenges != nil {
		if userChallenges, exists := c.challenges[userID]; exists && userChallenges != nil {
			if _, exists2 := userChallenges[challenge]; exists2 {
				userVerified = true
			}
		}
	}
	if !userVerified {
		http.Error(w, "verifiy user failure: miss JWT or/and challenge", http.StatusUnauthorized)
		return
	}

	var token *oauth2.Token
	var err error
	cacheMode := r.URL.Query().Get("cacheMode")
	if cacheMode == "persistence" {
		token, err = c.Service.GetAccessToken(provider, userID)
		if err != nil {
			http.Error(w, "get token error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		token, err = c.Service.GetAccessTokenWithoutStore(provider, userID)
		if err != nil {
			http.Error(w, "get token error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	resp := map[string]any{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    token.TokenType,
		"expires_in":    token.ExpiresIn,
		"expiry":        token.Expiry,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
