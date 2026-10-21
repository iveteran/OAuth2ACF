package model

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/oauth2"
)

type OAuthClient struct {
	Provider            string `json:"provider"`
	ClientID            string `json:"clientId"`
	ClientSecret        string `json:"clientSecret"`
	RedirectURI         string `json:"redirectUri"`
	Scopes              string `json:"scopes"`
	AuthURL             string `json:"authUrl"`
	TokenURL            string `json:"tokenUrl"`
	RefreshClientID     string `json:"refreshClientId,omitempty"`
	RefreshClientSecret string `json:"refreshClientSecret,omitempty"`
	RefreshScopes       string `json:"refreshScopes,omitempty"`
	RefreshTokenURL     string `json:"refreshTokenUrl,omitempty"`
}

// ProviderRefreshClient is the native/public OAuth client that issued the
// refresh tokens uploaded by the app. It is separate from the confidential web
// client used by /authorize and /callback.
type ProviderRefreshClient struct {
	Provider     string
	ClientID     string
	ClientSecret string
	Scopes       string
	TokenURL     string
}

var providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func InitClientsTable(db *sql.DB) error {
	// 配置表
	_, err := db.Exec(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
		provider TEXT PRIMARY KEY,
		client_id TEXT,
		client_secret TEXT,
		redirect_uri TEXT,
		scopes TEXT,
		auth_url TEXT,
		token_url TEXT
	);
	CREATE TABLE IF NOT EXISTS provider_refresh_clients (
		provider TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		client_secret TEXT NOT NULL,
		scopes TEXT NOT NULL,
		token_url TEXT NOT NULL
	)`)
	return err
}

func (c *OAuthClient) ToConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURI,
		Scopes:       strings.Split(c.Scopes, ","),
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.AuthURL,
			TokenURL: c.TokenURL,
		},
	}
}

func (c *ProviderRefreshClient) ToConfig() *oauth2.Config {
	authStyle := oauth2.AuthStyleAutoDetect
	if c.ClientSecret == "" {
		authStyle = oauth2.AuthStyleInParams
	}
	var scopes []string
	if c.Scopes != "" {
		scopes = strings.Split(c.Scopes, ",")
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL:  c.TokenURL,
			AuthStyle: authStyle,
		},
	}
}

func GetOAuthClient(db *sql.DB, provider string) (*OAuthClient, error) {
	row := db.QueryRow(`SELECT provider, client_id, client_secret,
	redirect_uri, scopes, auth_url, token_url
	FROM oauth_clients
	WHERE lower(provider)=lower(?)`,
		provider)
	c := &OAuthClient{}
	if err := row.Scan(
		&c.Provider,
		&c.ClientID,
		&c.ClientSecret,
		&c.RedirectURI,
		&c.Scopes,
		&c.AuthURL,
		&c.TokenURL); err != nil {
		return nil, err
	}
	return c, nil
}

// GetProviderRefreshClient returns the explicit native refresh client when one
// is configured. Existing installations fall back to their web OAuth client so
// the schema migration itself does not interrupt service.
func GetProviderRefreshClient(db *sql.DB, provider string) (*ProviderRefreshClient, error) {
	row := db.QueryRow(`SELECT provider,client_id,client_secret,scopes,token_url
		FROM provider_refresh_clients WHERE lower(provider)=lower(?)`, provider)
	client := &ProviderRefreshClient{}
	if err := row.Scan(&client.Provider, &client.ClientID, &client.ClientSecret, &client.Scopes, &client.TokenURL); err == nil {
		return client, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	legacy, err := GetOAuthClient(db, provider)
	if err != nil {
		return nil, err
	}
	return &ProviderRefreshClient{Provider: legacy.Provider, ClientID: legacy.ClientID,
		ClientSecret: legacy.ClientSecret, Scopes: legacy.Scopes, TokenURL: legacy.TokenURL}, nil
}

// ImportOAuthClients validates and upserts a declarative client configuration.
// Existing providers omitted from the file remain in the database.
func ImportOAuthClients(ctx context.Context, db *sql.DB, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.New("OAuth client configuration unavailable")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var clients []OAuthClient
	if err = decoder.Decode(&clients); err != nil {
		return errors.New("invalid OAuth client configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(clients) == 0 || len(clients) > 16 {
		return errors.New("invalid OAuth client configuration")
	}
	seen := make(map[string]bool, len(clients))
	for i := range clients {
		normalizeOAuthClient(&clients[i])
		if err = validateOAuthClient(clients[i]); err != nil || seen[clients[i].Provider] {
			return errors.New("invalid OAuth client configuration")
		}
		seen[clients[i].Provider] = true
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, client := range clients {
		if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_clients(provider,client_id,client_secret,redirect_uri,scopes,auth_url,token_url)
			VALUES(?,?,?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET
			client_id=excluded.client_id,client_secret=excluded.client_secret,redirect_uri=excluded.redirect_uri,
			scopes=excluded.scopes,auth_url=excluded.auth_url,token_url=excluded.token_url`,
			client.Provider, client.ClientID, client.ClientSecret, client.RedirectURI,
			client.Scopes, client.AuthURL, client.TokenURL); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM provider_refresh_clients WHERE provider=?`, client.Provider); err != nil {
			return err
		}
		if client.RefreshClientID != "" {
			if _, err = tx.ExecContext(ctx, `INSERT INTO provider_refresh_clients(provider,client_id,client_secret,scopes,token_url)
				VALUES(?,?,?,?,?)`, client.Provider, client.RefreshClientID, client.RefreshClientSecret,
				client.RefreshScopes, client.RefreshTokenURL); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func normalizeOAuthClient(client *OAuthClient) {
	client.Provider = strings.ToLower(strings.TrimSpace(client.Provider))
	client.ClientID = strings.TrimSpace(client.ClientID)
	client.ClientSecret = strings.TrimSpace(client.ClientSecret)
	client.RedirectURI = strings.TrimSpace(client.RedirectURI)
	client.Scopes = strings.TrimSpace(client.Scopes)
	client.AuthURL = strings.TrimSpace(client.AuthURL)
	client.TokenURL = strings.TrimSpace(client.TokenURL)
	client.RefreshClientID = strings.TrimSpace(client.RefreshClientID)
	client.RefreshClientSecret = strings.TrimSpace(client.RefreshClientSecret)
	client.RefreshScopes = strings.TrimSpace(client.RefreshScopes)
	client.RefreshTokenURL = strings.TrimSpace(client.RefreshTokenURL)
}

func validateOAuthClient(client OAuthClient) error {
	if !providerName.MatchString(client.Provider) ||
		client.ClientID == "" || client.ClientSecret == "" ||
		len(client.ClientID) > 4096 || len(client.ClientSecret) > 16384 ||
		len(client.RedirectURI) > 4096 || len(client.Scopes) > 8192 ||
		strings.ContainsAny(client.ClientID+client.ClientSecret+client.Scopes, "\x00\r\n") {
		return errors.New("invalid OAuth client")
	}
	for _, scope := range strings.Split(client.Scopes, ",") {
		if strings.TrimSpace(scope) == "" {
			return errors.New("invalid OAuth scopes")
		}
	}
	if !secureURL(client.AuthURL, false) || !secureURL(client.TokenURL, false) || !secureURL(client.RedirectURI, true) {
		return errors.New("invalid OAuth URL")
	}
	hasRefresh := client.RefreshClientID != "" || client.RefreshClientSecret != "" ||
		client.RefreshScopes != "" || client.RefreshTokenURL != ""
	if hasRefresh {
		if client.RefreshClientID == "" ||
			len(client.RefreshClientID) > 4096 || len(client.RefreshClientSecret) > 16384 ||
			len(client.RefreshScopes) > 8192 ||
			strings.ContainsAny(client.RefreshClientID+client.RefreshClientSecret+client.RefreshScopes, "\x00\r\n") ||
			!secureURL(client.RefreshTokenURL, false) {
			return errors.New("invalid provider refresh client")
		}
		if client.RefreshScopes != "" {
			for _, scope := range strings.Split(client.RefreshScopes, ",") {
				if strings.TrimSpace(scope) == "" {
					return errors.New("invalid provider refresh scopes")
				}
			}
		}
	}
	return nil
}

func secureURL(raw string, allowLoopbackHTTP bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	return allowLoopbackHTTP && parsed.Scheme == "http" &&
		(host == "localhost" || host == "127.0.0.1" || host == "::1")
}
