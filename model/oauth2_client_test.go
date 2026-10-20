package model

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestImportOAuthClients(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:oauth-client-import?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = InitClientsTable(db); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "clients.json")
	if err = os.WriteFile(path, []byte(`[
		{
			"provider": "Google",
			"clientId": "client-id",
			"clientSecret": "client-secret",
			"redirectUri": "https://accounts.example.com/callback",
			"scopes": "openid,email,profile",
			"authUrl": "https://accounts.google.com/o/oauth2/v2/auth",
			"tokenUrl": "https://oauth2.googleapis.com/token"
		}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = ImportOAuthClients(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	client, err := GetOAuthClient(db, "google")
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientID != "client-id" || client.Provider != "google" {
		t.Fatalf("unexpected imported client: %#v", client)
	}

	updated := []byte(`[{
		"provider":"google","clientId":"new-id","clientSecret":"new-secret",
		"redirectUri":"https://accounts.example.com/callback",
		"scopes":"openid,email","authUrl":"https://accounts.google.com/o/oauth2/v2/auth",
		"tokenUrl":"https://oauth2.googleapis.com/token"
	}]`)
	if err = os.WriteFile(path, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = ImportOAuthClients(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	client, err = GetOAuthClient(db, "google")
	if err != nil || client.ClientID != "new-id" {
		t.Fatalf("client was not updated: %#v %v", client, err)
	}
}

func TestImportOAuthClientsRejectsUnsafeConfiguration(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:oauth-client-invalid?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = InitClientsTable(db); err != nil {
		t.Fatal(err)
	}
	configurations := []string{
		`[]`,
		`[{"provider":"google","clientId":"id","clientSecret":"secret","redirectUri":"http://accounts.example.com/callback","scopes":"openid","authUrl":"https://accounts.google.com/auth","tokenUrl":"https://oauth2.googleapis.com/token"}]`,
		`[{"provider":"google","clientId":"id","clientSecret":"secret","redirectUri":"https://accounts.example.com/callback","scopes":"openid","authUrl":"http://accounts.google.com/auth","tokenUrl":"https://oauth2.googleapis.com/token"}]`,
		`[{"provider":"google","clientId":"id","clientSecret":"secret","redirectUri":"https://accounts.example.com/callback","scopes":"openid,","authUrl":"https://accounts.google.com/auth","tokenUrl":"https://oauth2.googleapis.com/token"}]`,
		`[{"provider":"google","clientId":"id","clientSecret":"secret","redirectUri":"https://accounts.example.com/callback","scopes":"openid","authUrl":"https://accounts.google.com/auth","tokenUrl":"https://oauth2.googleapis.com/token","extra":true}]`,
	}
	for i, raw := range configurations {
		path := filepath.Join(t.TempDir(), "invalid.json")
		if err = os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if err = ImportOAuthClients(context.Background(), db, path); err == nil {
			t.Fatalf("unsafe configuration %d was accepted", i)
		}
	}
}
