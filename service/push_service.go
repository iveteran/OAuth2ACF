package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iveteran/OAuth2ACF/model"
	"github.com/iveteran/OAuth2ACF/util"
	"golang.org/x/oauth2"
)

const pushSessionLifetime = 90 * 24 * time.Hour

type PushAccountProof struct {
	AccountID    string         `json:"accountId"`
	Provider     string         `json:"provider"`
	AccessToken  string         `json:"accessToken"`
	RefreshToken string         `json:"refreshToken,omitempty"`
	IMAP         *PushIMAPProof `json:"imap,omitempty"`
}

type PushIMAPProof struct {
	Email          string `json:"email"`
	Address        string `json:"address"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	TLS            string `json:"tls"`
	Mailbox        string `json:"mailbox,omitempty"`
	PollSeconds    int    `json:"pollSeconds,omitempty"`
	RecheckSeconds int    `json:"recheckSeconds,omitempty"`
	MaxMessages    int    `json:"maxMessages,omitempty"`
}

type PushTokenRequest struct {
	Accounts []PushAccountProof `json:"accounts"`
}

type PushTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	SessionToken string `json:"sessionToken"`
	ExpiresAt    string `json:"expiresAt"`
}

type ProviderConnection struct {
	Subject   string `json:"subject"`
	AccountID string `json:"accountId"`
	Provider  string `json:"provider"`
	Address   string `json:"address"`
}

type IMAPConnection struct {
	Subject        string `json:"subject"`
	AccountID      string `json:"accountId"`
	Address        string `json:"address"`
	Username       string `json:"username"`
	TLS            string `json:"tls"`
	Mailbox        string `json:"mailbox"`
	PollSeconds    int    `json:"pollSeconds"`
	RecheckSeconds int    `json:"recheckSeconds"`
	MaxMessages    int    `json:"maxMessages"`
	Revision       string `json:"revision"`
}

type PushService struct {
	DB         *sql.DB
	SigningKey ed25519.PrivateKey
	Issuer     string
	Audience   string
	HTTPClient *http.Client
	VerifyIMAP func(context.Context, PushIMAPProof) error
	Now        func() time.Time
}

// ProviderTokenFailure exposes only fields safe for operational logs. The
// wrapped error remains available to tests and callers, but controllers must
// never log it because provider descriptions can contain credential material.
type ProviderTokenFailure struct {
	Provider  string
	Reason    string
	Status    int
	OAuthCode string
	err       error
}

func (e *ProviderTokenFailure) Error() string { return "provider authorization unavailable" }
func (e *ProviderTokenFailure) Unwrap() error { return e.err }

func (s *PushService) InitDB() error {
	if err := model.InitClientsTable(s.DB); err != nil {
		return err
	}
	_, err := s.DB.Exec(`
	CREATE TABLE IF NOT EXISTS push_sessions (
		subject TEXT PRIMARY KEY,
		token_hash BLOB NOT NULL UNIQUE,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS provider_connections (
		subject TEXT NOT NULL,
		account_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		provider_user_id TEXT NOT NULL,
		provider_address TEXT NOT NULL,
		refresh_token TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY(subject, account_id),
		FOREIGN KEY(subject) REFERENCES push_sessions(subject) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS provider_connections_account
		ON provider_connections(account_id, provider);
	CREATE TABLE IF NOT EXISTS imap_connections (
		subject TEXT NOT NULL,
		account_id TEXT NOT NULL,
		address TEXT NOT NULL,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		tls TEXT NOT NULL,
		mailbox TEXT NOT NULL,
		poll_seconds INTEGER NOT NULL,
		recheck_seconds INTEGER NOT NULL,
		max_messages INTEGER NOT NULL,
		config_hash BLOB NOT NULL,
		revision TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY(subject, account_id),
		FOREIGN KEY(subject) REFERENCES push_sessions(subject) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS imap_connections_account
		ON imap_connections(account_id);
	`)
	return err
}

func (s *PushService) Exchange(ctx context.Context, authorization string, req PushTokenRequest) (PushTokenResponse, error) {
	if len(req.Accounts) > 32 {
		return PushTokenResponse{}, errors.New("too many accounts")
	}
	now := s.now()
	subject, err := s.sessionSubject(ctx, authorization, now)
	newSession := false
	if err != nil {
		if authorization != "" || len(req.Accounts) == 0 {
			return PushTokenResponse{}, errors.New("unauthorized")
		}
		subject, err = randomHex(32)
		if err != nil {
			return PushTokenResponse{}, err
		}
		newSession = true
	}

	verified := make([]verifiedAccount, 0, len(req.Accounts))
	seen := map[string]bool{}
	for _, proof := range req.Accounts {
		account, verifyErr := s.verifyProof(ctx, proof)
		if verifyErr != nil || seen[account.AccountID] {
			return PushTokenResponse{}, errors.New("account proof rejected")
		}
		seen[account.AccountID] = true
		verified = append(verified, account)
	}

	sessionToken, err := randomHex(32)
	if err != nil {
		return PushTokenResponse{}, err
	}
	hash := sha256.Sum256([]byte(sessionToken))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return PushTokenResponse{}, err
	}
	defer tx.Rollback()
	if newSession {
		if _, err = tx.ExecContext(ctx, `INSERT INTO push_sessions(subject,token_hash,created_at,updated_at) VALUES(?,?,?,?)`, subject, hash[:], now, now); err != nil {
			return PushTokenResponse{}, err
		}
	} else if _, err = tx.ExecContext(ctx, `UPDATE push_sessions SET token_hash=?,updated_at=? WHERE subject=?`, hash[:], now, subject); err != nil {
		return PushTokenResponse{}, err
	}
	if len(verified) > 0 {
		for _, account := range verified {
			if account.IMAP != nil {
				if err = upsertIMAPConnection(ctx, tx, subject, account.AccountID, *account.IMAP, now); err != nil {
					return PushTokenResponse{}, err
				}
				if _, err = tx.ExecContext(ctx, `DELETE FROM provider_connections WHERE subject=? AND account_id=?`, subject, account.AccountID); err != nil {
					return PushTokenResponse{}, err
				}
				continue
			}
			if account.RefreshToken == "" {
				var existing string
				_ = tx.QueryRowContext(ctx, `SELECT refresh_token FROM provider_connections WHERE subject=? AND account_id=?`, subject, account.AccountID).Scan(&existing)
				account.RefreshToken = existing
			}
			if account.RefreshToken == "" {
				return PushTokenResponse{}, errors.New("refresh token required for a new connection")
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO provider_connections(subject,account_id,provider,provider_user_id,provider_address,refresh_token,updated_at)
				VALUES(?,?,?,?,?,?,?) ON CONFLICT(subject,account_id) DO UPDATE SET provider=excluded.provider,provider_user_id=excluded.provider_user_id,provider_address=excluded.provider_address,refresh_token=excluded.refresh_token,updated_at=excluded.updated_at`, subject, account.AccountID, account.Provider, account.ProviderUserID, account.ProviderAddress, account.RefreshToken, now); err != nil {
				return PushTokenResponse{}, err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM imap_connections WHERE subject=? AND account_id=?`, subject, account.AccountID); err != nil {
				return PushTokenResponse{}, err
			}
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(verified)), ",")
		args := []any{subject}
		for _, account := range verified {
			args = append(args, account.AccountID)
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM provider_connections WHERE subject=? AND account_id NOT IN (`+placeholders+`)`, args...); err != nil {
			return PushTokenResponse{}, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM imap_connections WHERE subject=? AND account_id NOT IN (`+placeholders+`)`, args...); err != nil {
			return PushTokenResponse{}, err
		}
	}
	accounts, err := connectionAccountIDs(ctx, tx, subject)
	if err != nil || len(accounts) == 0 {
		return PushTokenResponse{}, errors.New("no authorized accounts")
	}
	if err = tx.Commit(); err != nil {
		return PushTokenResponse{}, err
	}
	expires := now.Add(10 * time.Minute)
	claims := jwt.MapClaims{
		"iss":        s.Issuer,
		"aud":        s.Audience,
		"sub":        subject,
		"accountIds": accounts,
		"iat":        now.Unix(),
		"exp":        expires.Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(s.SigningKey)
	if err != nil {
		return PushTokenResponse{}, err
	}
	return PushTokenResponse{AccessToken: token, SessionToken: sessionToken, ExpiresAt: expires.UTC().Format(time.RFC3339)}, nil
}

func (s *PushService) Connections(ctx context.Context) ([]ProviderConnection, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT subject,account_id,provider,provider_address FROM provider_connections ORDER BY subject,account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ProviderConnection
	for rows.Next() {
		var connection ProviderConnection
		if err = rows.Scan(&connection.Subject, &connection.AccountID, &connection.Provider, &connection.Address); err != nil {
			return nil, err
		}
		result = append(result, connection)
	}
	return result, rows.Err()
}

func (s *PushService) IMAPConnections(ctx context.Context) ([]IMAPConnection, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT subject,account_id,address,username,tls,mailbox,poll_seconds,recheck_seconds,max_messages,revision FROM imap_connections ORDER BY subject,account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []IMAPConnection
	for rows.Next() {
		var connection IMAPConnection
		if err = rows.Scan(&connection.Subject, &connection.AccountID, &connection.Address, &connection.Username, &connection.TLS, &connection.Mailbox, &connection.PollSeconds, &connection.RecheckSeconds, &connection.MaxMessages, &connection.Revision); err != nil {
			return nil, err
		}
		result = append(result, connection)
	}
	return result, rows.Err()
}

func (s *PushService) IMAPPassword(ctx context.Context, subject, accountID string) (string, error) {
	var encrypted string
	if err := s.DB.QueryRowContext(ctx, `SELECT password FROM imap_connections WHERE subject=? AND account_id=?`, subject, accountID).Scan(&encrypted); err != nil {
		return "", err
	}
	plain, err := util.Decrypt(encrypted)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *PushService) RevokeSession(ctx context.Context, authorization string) error {
	subject, err := s.sessionSubject(ctx, authorization, s.now())
	if err != nil {
		return err
	}
	result, err := s.DB.ExecContext(ctx, `DELETE FROM push_sessions WHERE subject=?`, subject)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted != 1 {
		return errors.New("session not found")
	}
	return nil
}

func (s *PushService) ProviderToken(ctx context.Context, subject, accountID string) (*oauth2.Token, error) {
	var provider, encrypted string
	err := s.DB.QueryRowContext(ctx, `SELECT provider,refresh_token FROM provider_connections WHERE subject=? AND account_id=?`, subject, accountID).Scan(&provider, &encrypted)
	if err != nil {
		return nil, &ProviderTokenFailure{Reason: "connection_lookup", err: err}
	}
	plain, err := util.Decrypt(encrypted)
	if err != nil {
		return nil, &ProviderTokenFailure{Provider: provider, Reason: "credential_decrypt", err: err}
	}
	client, err := model.GetProviderRefreshClient(s.DB, provider)
	if err != nil {
		return nil, &ProviderTokenFailure{Provider: provider, Reason: "client_configuration", err: err}
	}
	token, err := client.ToConfig().TokenSource(ctx, &oauth2.Token{RefreshToken: string(plain)}).Token()
	if err != nil {
		failure := &ProviderTokenFailure{Provider: provider, Reason: "token_endpoint", OAuthCode: "unknown", err: err}
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) {
			failure.OAuthCode = safeOAuthCode(retrieve.ErrorCode)
			if retrieve.Response != nil {
				failure.Status = retrieve.Response.StatusCode
			}
		}
		return nil, failure
	}
	if token.RefreshToken != "" && token.RefreshToken != string(plain) {
		rotated, sealErr := util.Encrypt([]byte(token.RefreshToken))
		if sealErr != nil {
			return nil, sealErr
		}
		_, err = s.DB.ExecContext(ctx, `UPDATE provider_connections SET refresh_token=?,updated_at=? WHERE subject=? AND account_id=?`, rotated, s.now(), subject, accountID)
		if err != nil {
			return nil, err
		}
	}
	return token, nil
}

func safeOAuthCode(value string) string {
	if value == "" || len(value) > 64 {
		return "unknown"
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return "unknown"
		}
	}
	return value
}

type verifiedAccount struct {
	AccountID, Provider, ProviderUserID, ProviderAddress, RefreshToken string
	IMAP                                                               *verifiedIMAP
}

func (s *PushService) verifyProof(ctx context.Context, proof PushAccountProof) (verifiedAccount, error) {
	if proof.Provider == "selfhosted" {
		return s.verifyIMAPProof(ctx, proof)
	}
	if proof.AccountID == "" || proof.AccessToken == "" || (proof.Provider != "google" && proof.Provider != "microsoft") {
		return verifiedAccount{}, errors.New("invalid proof")
	}
	endpoint := "https://www.googleapis.com/oauth2/v3/userinfo"
	if proof.Provider == "microsoft" {
		endpoint = "https://graph.microsoft.com/v1.0/me?$select=id,mail,userPrincipalName"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return verifiedAccount{}, err
	}
	request.Header.Set("Authorization", "Bearer "+proof.AccessToken)
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return verifiedAccount{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return verifiedAccount{}, errors.New("provider rejected proof")
	}
	var profile struct {
		Sub               string `json:"sub"`
		ID                string `json:"id"`
		Email             string `json:"email"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&profile); err != nil {
		return verifiedAccount{}, err
	}
	providerID := profile.Sub
	if proof.Provider == "microsoft" {
		providerID = profile.ID
	}
	address := profile.Email
	if proof.Provider == "microsoft" {
		address = profile.Mail
		if address == "" {
			address = profile.UserPrincipalName
		}
	}
	if providerID == "" || address == "" || proof.AccountID != proof.Provider+":"+providerID {
		return verifiedAccount{}, errors.New("account identity mismatch")
	}
	refresh := ""
	if proof.RefreshToken != "" {
		refresh, err = util.Encrypt([]byte(proof.RefreshToken))
		if err != nil {
			return verifiedAccount{}, err
		}
	}
	return verifiedAccount{AccountID: proof.AccountID, Provider: proof.Provider, ProviderUserID: providerID, ProviderAddress: strings.ToLower(address), RefreshToken: refresh}, nil
}

func (s *PushService) sessionSubject(ctx context.Context, authorization string, now time.Time) (string, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return "", errors.New("missing session")
	}
	hash := sha256.Sum256([]byte(strings.TrimPrefix(authorization, "Bearer ")))
	var subject string
	var updated time.Time
	err := s.DB.QueryRowContext(ctx, `SELECT subject,updated_at FROM push_sessions WHERE token_hash=?`, hash[:]).Scan(&subject, &updated)
	if err != nil || now.Sub(updated) > pushSessionLifetime {
		return "", errors.New("invalid session")
	}
	return subject, nil
}

func connectionAccountIDs(ctx context.Context, tx *sql.Tx, subject string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT account_id FROM provider_connections WHERE subject=? UNION SELECT account_id FROM imap_connections WHERE subject=? ORDER BY account_id`, subject, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *PushService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
