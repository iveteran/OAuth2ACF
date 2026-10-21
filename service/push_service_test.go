package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
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

func TestProviderTokenUsesPublicRefreshClient(t *testing.T) {
	t.Setenv("OAUTH2ACF_TOKEN_KEY", "test-provider-token-key")
	db, err := sql.Open("sqlite3", "file:provider-refresh-test?mode=memory&cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, privateKey, _ := ed25519.GenerateKey(nil)
	service := &PushService{
		DB: db, SigningKey: privateKey, Issuer: "issuer", Audience: "audience",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"sub":"subject-1","email":"test@example.com"}`)), Header: make(http.Header)}, nil
		})},
	}
	if err = service.InitDB(); err != nil {
		t.Fatal(err)
	}
	issued, err := service.Exchange(context.Background(), "", PushTokenRequest{Accounts: []PushAccountProof{{
		AccountID: "google:subject-1", Provider: "google", AccessToken: "access", RefreshToken: "refresh-old",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO provider_refresh_clients(provider,client_id,client_secret,scopes,token_url) VALUES(?,?,?,?,?)`,
		"google", "native-client", "", "openid,email", "placeholder"); err != nil {
		t.Fatal(err)
	}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_id") != "native-client" || r.Form.Get("client_secret") != "" ||
			r.Form.Get("refresh_token") != "refresh-old" || r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected refresh request: form=%v authorization=%q", r.Form, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access-new","refresh_token":"refresh-new","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokenServer.Close()
	if _, err = db.Exec(`UPDATE provider_refresh_clients SET token_url=? WHERE provider='google'`, tokenServer.URL); err != nil {
		t.Fatal(err)
	}
	connections, err := service.Connections(context.Background())
	if err != nil || len(connections) != 1 {
		t.Fatalf("unexpected connections: %#v %v", connections, err)
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, tokenServer.Client())
	token, err := service.ProviderToken(ctx, connections[0].Subject, connections[0].AccountID)
	if err != nil || token.AccessToken != "access-new" {
		t.Fatalf("public refresh failed: %#v %v", token, err)
	}
	if err = service.RevokeSession(context.Background(), "Bearer "+issued.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestPushExchangeStoresVerifiedIMAPConnectionAndRotatesRevision(t *testing.T) {
	t.Setenv("OAUTH2ACF_TOKEN_KEY", "test-provider-token-key")
	db, err := sql.Open("sqlite3", "file:imap-push-test?mode=memory&cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	service := &PushService{
		DB: db, SigningKey: privateKey, Issuer: "https://accounts.example", Audience: "icchat-push",
		VerifyIMAP: func(_ context.Context, proof PushIMAPProof) error {
			verified++
			if proof.Username != "user@example.com" || proof.Password == "" {
				t.Fatal("unexpected IMAP proof")
			}
			return nil
		},
	}
	if err = service.InitDB(); err != nil {
		t.Fatal(err)
	}
	request := PushTokenRequest{Accounts: []PushAccountProof{{
		AccountID: "selfHosted:user@example.com", Provider: "selfhosted",
		IMAP: &PushIMAPProof{Email: "user@example.com", Address: "imap.example.com:993", Username: "user@example.com", Password: "secret", TLS: "tls"},
	}}}
	issued, err := service.Exchange(context.Background(), "", request)
	if err != nil {
		t.Fatal(err)
	}
	connections, err := service.IMAPConnections(context.Background())
	if err != nil || len(connections) != 1 {
		t.Fatalf("unexpected IMAP connections: %#v, %v", connections, err)
	}
	firstRevision := connections[0].Revision
	if connections[0].Mailbox != "INBOX" || connections[0].PollSeconds != 120 || firstRevision == "" {
		t.Fatalf("defaults or revision missing: %#v", connections[0])
	}
	password, err := service.IMAPPassword(context.Background(), connections[0].Subject, connections[0].AccountID)
	if err != nil || password != "secret" {
		t.Fatalf("password did not round trip: %q, %v", password, err)
	}

	second, err := service.Exchange(context.Background(), "Bearer "+issued.SessionToken, request)
	if err != nil {
		t.Fatal(err)
	}
	connections, _ = service.IMAPConnections(context.Background())
	if connections[0].Revision != firstRevision {
		t.Fatal("unchanged credentials restarted the monitor")
	}
	request.Accounts[0].IMAP.Password = "rotated"
	third, err := service.Exchange(context.Background(), "Bearer "+second.SessionToken, request)
	if err != nil {
		t.Fatal(err)
	}
	connections, _ = service.IMAPConnections(context.Background())
	if connections[0].Revision == firstRevision {
		t.Fatal("credential rotation did not change monitor revision")
	}
	if verified != 3 {
		t.Fatalf("proof verifier called %d times", verified)
	}
	if err = service.RevokeSession(context.Background(), "Bearer "+third.SessionToken); err != nil {
		t.Fatal(err)
	}
	connections, err = service.IMAPConnections(context.Background())
	if err != nil || len(connections) != 0 {
		t.Fatalf("IMAP connection retained after revoke: %#v, %v", connections, err)
	}
}

func TestPushExchangeRejectsInsecureOrMismatchedIMAPProof(t *testing.T) {
	t.Setenv("OAUTH2ACF_TOKEN_KEY", "test-provider-token-key")
	db, err := sql.Open("sqlite3", "file:invalid-imap-push-test?mode=memory&cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, privateKey, _ := ed25519.GenerateKey(nil)
	service := &PushService{DB: db, SigningKey: privateKey, Issuer: "issuer", Audience: "audience", VerifyIMAP: func(context.Context, PushIMAPProof) error {
		t.Fatal("invalid proof reached the network verifier")
		return nil
	}}
	if err = service.InitDB(); err != nil {
		t.Fatal(err)
	}
	for _, proof := range []PushAccountProof{
		{AccountID: "selfHosted:other@example.com", Provider: "selfhosted", IMAP: &PushIMAPProof{Email: "user@example.com", Address: "imap.example.com:993", Username: "user", Password: "secret", TLS: "tls"}},
		{AccountID: "selfHosted:user@example.com", Provider: "selfhosted", IMAP: &PushIMAPProof{Email: "user@example.com", Address: "imap.example.com:143", Username: "user", Password: "secret", TLS: "plain"}},
	} {
		if _, err = service.Exchange(context.Background(), "", PushTokenRequest{Accounts: []PushAccountProof{proof}}); err == nil {
			t.Fatal("invalid IMAP proof was accepted")
		}
	}
}

func TestIMAPProofDialTargetRejectsPrivateNetworks(t *testing.T) {
	for _, address := range []string{"127.0.0.1:993", "10.0.0.1:993", "100.64.0.1:993", "[::1]:993"} {
		if _, err := publicIMAPDialAddress(context.Background(), address); err == nil {
			t.Fatalf("private IMAP target %s was accepted", address)
		}
	}
	address, err := publicIMAPDialAddress(context.Background(), "8.8.8.8:993")
	if err != nil || address != "8.8.8.8:993" {
		t.Fatalf("public IMAP target rejected: %q %v", address, err)
	}
}
