package service

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/iveteran/OAuth2ACF/util"
)

type PushJMAPProof struct {
	Email      string `json:"email"`
	SessionURL string `json:"sessionUrl"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}
type verifiedJMAP struct {
	SessionURL, Username, Password, Revision string
	Hash                                     []byte
}
type JMAPConnection struct {
	Subject    string `json:"subject"`
	AccountID  string `json:"accountId"`
	SessionURL string `json:"sessionUrl"`
	Username   string `json:"username"`
	Revision   string `json:"revision"`
}

func (s *PushService) verifyJMAPProof(ctx context.Context, proof PushAccountProof) (verifiedAccount, error) {
	if proof.JMAP == nil || proof.IMAP != nil || proof.AccessToken != "" || proof.RefreshToken != "" {
		return verifiedAccount{}, errors.New("invalid JMAP proof")
	}
	c := *proof.JMAP
	c.Email = strings.ToLower(strings.TrimSpace(c.Email))
	u, err := url.Parse(c.SessionURL)
	email, ok := strings.CutPrefix(proof.AccountID, "selfHosted:")
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(c.SessionURL) > 4096 || !ok || c.Email == "" || !strings.EqualFold(email, c.Email) || c.Username == "" || len(c.Username) > 1024 || c.Password == "" || len(c.Password) > 65536 || strings.ContainsAny(c.Username+c.Password, "\x00\r\n") {
		return verifiedAccount{}, errors.New("invalid JMAP identity or endpoint")
	}
	verify := s.VerifyJMAP
	if verify == nil {
		verify = verifyJMAPLogin
	}
	if err = verify(ctx, c); err != nil {
		return verifiedAccount{}, errors.New("JMAP proof rejected")
	}
	encrypted, err := util.Encrypt([]byte(c.Password))
	if err != nil {
		return verifiedAccount{}, err
	}
	raw, _ := json.Marshal(c)
	revision, err := randomHex(16)
	if err != nil {
		return verifiedAccount{}, err
	}
	return verifiedAccount{AccountID: proof.AccountID, Provider: "selfhosted", ProviderAddress: c.Email, JMAP: &verifiedJMAP{SessionURL: c.SessionURL, Username: c.Username, Password: encrypted, Revision: revision, Hash: util.Fingerprint(raw)}}, nil
}
func upsertJMAPConnection(ctx context.Context, tx *sql.Tx, subject, accountID string, c verifiedJMAP, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO jmap_connections(subject,account_id,session_url,username,password,config_hash,revision,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject,account_id) DO UPDATE SET session_url=excluded.session_url,username=excluded.username,password=excluded.password,config_hash=excluded.config_hash,revision=CASE WHEN jmap_connections.config_hash=excluded.config_hash THEN jmap_connections.revision ELSE excluded.revision END,updated_at=excluded.updated_at`, subject, accountID, c.SessionURL, c.Username, c.Password, c.Hash, c.Revision, now)
	return err
}
func (s *PushService) JMAPConnections(ctx context.Context) ([]JMAPConnection, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT subject,account_id,session_url,username,revision FROM jmap_connections ORDER BY subject,account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []JMAPConnection
	for rows.Next() {
		var c JMAPConnection
		if err = rows.Scan(&c.Subject, &c.AccountID, &c.SessionURL, &c.Username, &c.Revision); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
func (s *PushService) JMAPPassword(ctx context.Context, subject, accountID string) (string, error) {
	var encrypted string
	if err := s.DB.QueryRowContext(ctx, `SELECT password FROM jmap_connections WHERE subject=? AND account_id=?`, subject, accountID).Scan(&encrypted); err != nil {
		return "", err
	}
	plain, err := util.Decrypt(encrypted)
	return string(plain), err
}

// Resolve and pin a public address on every dial. Do not use environment
// proxies or redirects that could forward a mailbox password to another host.
func jmapHTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target, err := publicIMAPDialAddress(ctx, address)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, target)
		},
	}, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || r.URL.Scheme != "https" || r.URL.Host != via[0].URL.Host || r.URL.User != nil {
			return errors.New("unsafe JMAP redirect")
		}
		return nil
	}}
}
func verifyJMAPLogin(ctx context.Context, c PushJMAPProof) error {
	client := jmapHTTPClient()
	defer client.CloseIdleConnections()
	return verifyJMAPWithClient(ctx, c, client)
}
func verifyJMAPWithClient(ctx context.Context, c PushJMAPProof, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.SessionURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return errors.New("JMAP session unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("JMAP authentication rejected")
	}
	var session struct {
		APIURL  string            `json:"apiUrl"`
		Primary map[string]string `json:"primaryAccounts"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&session); err != nil {
		return err
	}
	account := session.Primary["urn:ietf:params:jmap:mail"]
	if account == "" || session.APIURL == "" {
		return errors.New("no JMAP mail account")
	}
	endpoint, err := res.Request.URL.Parse(session.APIURL)
	origin, _ := url.Parse(c.SessionURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host != origin.Host || endpoint.User != nil {
		return errors.New("unsafe JMAP API endpoint")
	}
	// Empty ids asks only for the global Email state, never message contents.
	body, _ := json.Marshal(map[string]any{"using": []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"}, "methodCalls": []any{[]any{"Email/get", map[string]any{"accountId": account, "ids": []string{}}, "verify"}}})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("JMAP mail unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("JMAP mail rejected")
	}
	var payload struct {
		Responses []json.RawMessage `json:"methodResponses"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return err
	}
	if len(payload.Responses) != 1 {
		return errors.New("invalid JMAP response")
	}
	var tuple []json.RawMessage
	if json.Unmarshal(payload.Responses[0], &tuple) != nil || len(tuple) != 3 {
		return errors.New("invalid JMAP response")
	}
	var method, tag string
	var result struct {
		State     string `json:"state"`
		AccountID string `json:"accountId"`
	}
	if json.Unmarshal(tuple[0], &method) != nil || json.Unmarshal(tuple[1], &result) != nil || json.Unmarshal(tuple[2], &tag) != nil || method != "Email/get" || tag != "verify" || result.State == "" || result.AccountID != account {
		return errors.New("JMAP mail access rejected")
	}
	return nil
}
