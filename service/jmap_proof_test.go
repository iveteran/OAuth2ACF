package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJMAPExchangeRotationProtocolSwitchAndRevoke(t *testing.T) {
	t.Setenv("OAUTH2ACF_TOKEN_KEY", "test-provider-token-key")
	db, err := sql.Open("sqlite3", "file:jmap-push-test?mode=memory&cache=shared&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, key, _ := ed25519.GenerateKey(nil)
	s := &PushService{DB: db, SigningKey: key, Issuer: "issuer", Audience: "audience", VerifyJMAP: func(context.Context, PushJMAPProof) error { return nil }, VerifyIMAP: func(context.Context, PushIMAPProof) error { return nil }}
	if err = s.InitDB(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	proof := PushAccountProof{AccountID: "selfHosted:user@example.com", Provider: "selfhosted", JMAP: &PushJMAPProof{Email: "user@example.com", SessionURL: "https://mail.example.com/.well-known/jmap", Username: "user", Password: "secret"}}
	req := PushTokenRequest{Accounts: []PushAccountProof{proof}}
	issued, err := s.Exchange(ctx, "", req)
	if err != nil {
		t.Fatal(err)
	}
	connections, err := s.JMAPConnections(ctx)
	if err != nil || len(connections) != 1 {
		t.Fatal(connections, err)
	}
	first := connections[0]
	ids, err := connectionIDsForTest(db, first.Subject)
	if err != nil || len(ids) != 1 || ids[0] != proof.AccountID {
		t.Fatal(ids, err)
	}
	if password, err := s.JMAPPassword(ctx, first.Subject, first.AccountID); err != nil || password != "secret" {
		t.Fatal("credential did not round trip", err)
	}
	raw, _ := json.Marshal(connections)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "password") {
		t.Fatal("list leaked credentials")
	}
	var encrypted string
	if err = db.QueryRow(`SELECT password FROM jmap_connections`).Scan(&encrypted); err != nil || encrypted == "secret" {
		t.Fatal("credential not encrypted", err)
	}
	second, err := s.Exchange(ctx, "Bearer "+issued.SessionToken, req)
	if err != nil {
		t.Fatal(err)
	}
	connections, _ = s.JMAPConnections(ctx)
	if connections[0].Revision != first.Revision {
		t.Fatal("unchanged proof restarted watcher")
	}
	req.Accounts[0].JMAP.Password = "rotated"
	third, err := s.Exchange(ctx, "Bearer "+second.SessionToken, req)
	if err != nil {
		t.Fatal(err)
	}
	connections, _ = s.JMAPConnections(ctx)
	if connections[0].Revision == first.Revision {
		t.Fatal("rotation did not restart watcher")
	}
	// A protocol switch removes the old watcher from the same account atomically.
	req.Accounts[0].JMAP = nil
	req.Accounts[0].IMAP = &PushIMAPProof{Email: "user@example.com", Address: "mail.example.com:993", Username: "user", Password: "secret", TLS: "tls"}
	fourth, err := s.Exchange(ctx, "Bearer "+third.SessionToken, req)
	if err != nil {
		t.Fatal(err)
	}
	connections, _ = s.JMAPConnections(ctx)
	if len(connections) != 0 {
		t.Fatal("JMAP watcher survived protocol switch")
	}
	imaps, _ := s.IMAPConnections(ctx)
	if len(imaps) != 1 {
		t.Fatal("IMAP watcher missing")
	}
	req.Accounts[0] = proof
	fifth, err := s.Exchange(ctx, "Bearer "+fourth.SessionToken, req)
	if err != nil {
		t.Fatal(err)
	}
	imaps, _ = s.IMAPConnections(ctx)
	if len(imaps) != 0 {
		t.Fatal("IMAP watcher survived protocol switch")
	}
	if err = s.RevokeSession(ctx, "Bearer "+fifth.SessionToken); err != nil {
		t.Fatal(err)
	}
	connections, err = s.JMAPConnections(ctx)
	if err != nil || len(connections) != 0 {
		t.Fatal("watcher survived revoke", err)
	}
}
func connectionIDsForTest(db *sql.DB, subject string) ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return connectionAccountIDs(context.Background(), tx, subject)
}

func TestJMAPProofRejectsInvalidIdentityEndpointsAndMixedProofs(t *testing.T) {
	s := &PushService{VerifyJMAP: func(context.Context, PushJMAPProof) error { t.Fatal("invalid proof reached verifier"); return nil }}
	base := PushJMAPProof{Email: "user@example.com", SessionURL: "https://mail.example.com/.well-known/jmap", Username: "user", Password: "secret"}
	for _, endpoint := range []string{"http://mail.example.com/jmap", "https://user:password@mail.example.com/jmap", "https://mail.example.com/jmap?secret=1"} {
		c := base
		c.SessionURL = endpoint
		if _, err := s.verifyProof(context.Background(), PushAccountProof{AccountID: "selfHosted:user@example.com", Provider: "selfhosted", JMAP: &c}); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, p := range []PushAccountProof{
		{AccountID: "selfHosted:other@example.com", Provider: "selfhosted", JMAP: &base},
		{AccountID: "selfHosted:user@example.com", Provider: "selfhosted", JMAP: &base, AccessToken: "local-handle"},
		{AccountID: "selfHosted:user@example.com", Provider: "selfhosted", JMAP: &base, IMAP: &PushIMAPProof{}},
	} {
		if _, err := s.verifyProof(context.Background(), p); err == nil {
			t.Fatal("invalid proof accepted")
		}
	}
}
func TestJMAPVerificationChecksMailAccessWithoutReadingMessages(t *testing.T) {
	var baseURL string
	reject := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user" || password != "secret" {
			t.Error("missing basic auth")
			http.Error(w, "", 401)
			return
		}
		switch r.URL.Path {
		case "/.well-known/jmap":
			http.Redirect(w, r, "/session", http.StatusTemporaryRedirect)
		case "/session":
			json.NewEncoder(w).Encode(map[string]any{"apiUrl": baseURL + "/api", "primaryAccounts": map[string]string{"urn:ietf:params:jmap:mail": "a"}})
		case "/api":
			var request struct {
				Calls [][]json.RawMessage `json:"methodCalls"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			var args struct {
				IDs []string `json:"ids"`
			}
			json.Unmarshal(request.Calls[0][1], &args)
			if args.IDs == nil || len(args.IDs) != 0 {
				t.Error("must request empty ids")
			}
			method := "Email/get"
			if reject {
				method = "error"
			}
			json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, map[string]string{"accountId": "a", "state": "s1"}, "verify"}}})
		}
	}))
	defer server.Close()
	baseURL = server.URL
	c := PushJMAPProof{SessionURL: server.URL + "/.well-known/jmap", Username: "user", Password: "secret"}
	if err := verifyJMAPWithClient(context.Background(), c, server.Client()); err != nil {
		t.Fatal(err)
	}
	reject = true
	if err := verifyJMAPWithClient(context.Background(), c, server.Client()); err == nil {
		t.Fatal("method error authenticated account")
	}
	s := &PushService{VerifyJMAP: func(context.Context, PushJMAPProof) error { return errors.New("secret upstream") }}
	c.Email = "user@example.com"
	_, err := s.verifyJMAPProof(context.Background(), PushAccountProof{AccountID: "selfHosted:user@example.com", Provider: "selfhosted", JMAP: &c})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("unsafe verification error", err)
	}
}
