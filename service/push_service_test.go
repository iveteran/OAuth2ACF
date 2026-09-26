package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPushExchangeSignsScopedJWTAndRevokeDeletesConnections(t *testing.T) {
	t.Setenv("OAUTH2ACF_TOKEN_KEY", "test-provider-token-key")
	db, err := sql.Open("sqlite3", "file:push-test?mode=memory&cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 26, 8, 0, 0, 0, time.UTC)
	service := &PushService{
		DB: db, SigningKey: privateKey, Issuer: "https://accounts.example",
		Audience: "icchat-push", Now: func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Authorization") != "Bearer provider-access" {
				t.Fatalf("unexpected provider authorization")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"sub":"subject-1","email":"test@example.com"}`)),
				Header:     make(http.Header),
			}, nil
		})},
	}
	if err = service.InitDB(); err != nil {
		t.Fatal(err)
	}

	issued, err := service.Exchange(context.Background(), "", PushTokenRequest{Accounts: []PushAccountProof{{
		AccountID: "google:subject-1", Provider: "google", AccessToken: "provider-access", RefreshToken: "provider-refresh",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(issued.AccessToken, func(token *jwt.Token) (any, error) {
		return privateKey.Public(), nil
	}, jwt.WithAudience("icchat-push"), jwt.WithIssuer("https://accounts.example"), jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !parsed.Valid {
		t.Fatalf("invalid issued JWT: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	accounts, ok := claims["accountIds"].([]any)
	if !ok || len(accounts) != 1 || accounts[0] != "google:subject-1" {
		t.Fatalf("unexpected account claims: %#v", claims["accountIds"])
	}

	rotated, err := service.Exchange(context.Background(), "Bearer "+issued.SessionToken, PushTokenRequest{})
	if err != nil || rotated.SessionToken == issued.SessionToken {
		t.Fatalf("session rotation failed: %v", err)
	}
	if err = service.RevokeSession(context.Background(), "Bearer "+rotated.SessionToken); err != nil {
		t.Fatal(err)
	}
	connections, err := service.Connections(context.Background())
	if err != nil || len(connections) != 0 {
		t.Fatalf("connections retained after revoke: %#v, %v", connections, err)
	}
	if err = service.RevokeSession(context.Background(), "Bearer "+rotated.SessionToken); err == nil {
		t.Fatal("revoked session remained valid")
	}
}
