package controller

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/iveteran/OAuth2ACF/service"
)

type PushController struct {
	Service   *service.PushService
	BrokerKey string
}

func (c *PushController) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request service.PushTokenRequest
	if !decodePushJSON(w, r, &request) {
		return
	}
	response, err := c.Service.Exchange(r.Context(), r.Header.Get("Authorization"), request)
	if err != nil {
		writePushJSON(w, http.StatusUnauthorized, map[string]string{"error": "account authorization failed"})
		return
	}
	writePushJSON(w, http.StatusOK, response)
}

func (c *PushController) Session(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := c.Service.RevokeSession(r.Context(), r.Header.Get("Authorization")); err != nil {
		writePushJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *PushController) Connections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !c.internal(r) {
		writePushJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	connections, err := c.Service.Connections(r.Context())
	if err != nil {
		writePushJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
		return
	}
	writePushJSON(w, http.StatusOK, map[string]any{"connections": connections})
}

func (c *PushController) ProviderToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !c.internal(r) {
		writePushJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var request struct {
		Subject   string `json:"subject"`
		AccountID string `json:"accountId"`
	}
	if !decodePushJSON(w, r, &request) || request.Subject == "" || request.AccountID == "" {
		return
	}
	token, err := c.Service.ProviderToken(r.Context(), request.Subject, request.AccountID)
	if err != nil {
		var failure *service.ProviderTokenFailure
		if errors.As(err, &failure) {
			log.Printf("provider token unavailable provider=%s reason=%s status=%d oauth_error=%s",
				failure.Provider, failure.Reason, failure.Status, failure.OAuthCode)
		} else {
			log.Print("provider token unavailable reason=internal")
		}
		writePushJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider authorization unavailable"})
		return
	}
	writePushJSON(w, http.StatusOK, map[string]any{"accessToken": token.AccessToken, "expiresAt": token.Expiry})
}

func (c *PushController) IMAPConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !c.internal(r) {
		writePushJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	connections, err := c.Service.IMAPConnections(r.Context())
	if err != nil {
		writePushJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
		return
	}
	writePushJSON(w, http.StatusOK, map[string]any{"connections": connections})
}

func (c *PushController) IMAPPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !c.internal(r) {
		writePushJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var request struct {
		Subject   string `json:"subject"`
		AccountID string `json:"accountId"`
	}
	if !decodePushJSON(w, r, &request) || request.Subject == "" || request.AccountID == "" {
		return
	}
	password, err := c.Service.IMAPPassword(r.Context(), request.Subject, request.AccountID)
	if err != nil {
		writePushJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "IMAP authorization unavailable"})
		return
	}
	writePushJSON(w, http.StatusOK, map[string]string{"password": password})
}

func (c *PushController) internal(r *http.Request) bool {
	actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	expected := sha256.Sum256([]byte("Bearer " + c.BrokerKey))
	return len(c.BrokerKey) >= 32 && subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func decodePushJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		writePushJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "application/json required"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writePushJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writePushJSON(w, http.StatusBadRequest, map[string]string{"error": "single JSON object required"})
		return false
	}
	return true
}

func writePushJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
