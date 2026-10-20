package service

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/iveteran/OAuth2ACF/util"
)

type verifiedIMAP struct {
	Address, Username, Password, TLS, Mailbox, Revision string
	PollSeconds, RecheckSeconds, MaxMessages            int
	Hash                                                []byte
}

var carrierGradeNAT = func() *net.IPNet {
	_, network, _ := net.ParseCIDR("100.64.0.0/10")
	return network
}()

func (s *PushService) verifyIMAPProof(ctx context.Context, proof PushAccountProof) (verifiedAccount, error) {
	if proof.AccountID == "" || proof.IMAP == nil || proof.AccessToken != "" || proof.RefreshToken != "" {
		return verifiedAccount{}, errors.New("invalid IMAP proof")
	}
	c := *proof.IMAP
	c.Email = strings.ToLower(strings.TrimSpace(c.Email))
	c.Address = strings.TrimSpace(c.Address)
	c.Username = strings.TrimSpace(c.Username)
	if c.Mailbox == "" {
		c.Mailbox = "INBOX"
	}
	if c.TLS == "" {
		c.TLS = "tls"
	}
	if c.PollSeconds == 0 {
		c.PollSeconds = 120
	}
	if c.RecheckSeconds == 0 {
		c.RecheckSeconds = 300
	}
	if c.MaxMessages == 0 {
		c.MaxMessages = 100000
	}
	host, port, err := net.SplitHostPort(c.Address)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || portNumber < 1 || portNumber > 65535 || strings.ContainsAny(host, "\x00\r\n /\\") {
		return verifiedAccount{}, errors.New("invalid IMAP address")
	}
	accountEmail, hasPrefix := strings.CutPrefix(proof.AccountID, "selfHosted:")
	if c.Email == "" || !hasPrefix || !strings.EqualFold(accountEmail, c.Email) || c.Username == "" || c.Password == "" || len(c.Username) > 1024 || len(c.Password) > 65536 || len(c.Mailbox) > 1024 || strings.ContainsAny(c.Username+c.Password+c.Mailbox, "\x00\r\n") {
		return verifiedAccount{}, errors.New("invalid IMAP identity")
	}
	if c.TLS != "tls" && c.TLS != "starttls" {
		return verifiedAccount{}, errors.New("insecure IMAP transport")
	}
	if c.PollSeconds < 1 || c.PollSeconds > 3600 || c.RecheckSeconds < 1 || c.RecheckSeconds > 1500 || c.MaxMessages < 1 || c.MaxMessages > 1000000 {
		return verifiedAccount{}, errors.New("invalid IMAP monitor limits")
	}
	verify := s.VerifyIMAP
	if verify == nil {
		verify = verifyIMAPLogin
	}
	if err = verify(ctx, c); err != nil {
		return verifiedAccount{}, errors.New("IMAP proof rejected")
	}
	encrypted, err := util.Encrypt([]byte(c.Password))
	if err != nil {
		return verifiedAccount{}, err
	}
	fingerprint, _ := json.Marshal(c)
	hash := util.Fingerprint(fingerprint)
	revision, err := randomHex(16)
	if err != nil {
		return verifiedAccount{}, err
	}
	return verifiedAccount{AccountID: proof.AccountID, Provider: "selfhosted", ProviderAddress: c.Email, IMAP: &verifiedIMAP{
		Address: c.Address, Username: c.Username, Password: encrypted, TLS: c.TLS, Mailbox: c.Mailbox,
		PollSeconds: c.PollSeconds, RecheckSeconds: c.RecheckSeconds, MaxMessages: c.MaxMessages,
		Hash: hash, Revision: revision,
	}}, nil
}

func upsertIMAPConnection(ctx context.Context, tx *sql.Tx, subject, accountID string, c verifiedIMAP, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO imap_connections(subject,account_id,address,username,password,tls,mailbox,poll_seconds,recheck_seconds,max_messages,config_hash,revision,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(subject,account_id) DO UPDATE SET
		address=excluded.address,username=excluded.username,password=excluded.password,tls=excluded.tls,mailbox=excluded.mailbox,
		poll_seconds=excluded.poll_seconds,recheck_seconds=excluded.recheck_seconds,max_messages=excluded.max_messages,
		config_hash=excluded.config_hash,revision=CASE WHEN imap_connections.config_hash=excluded.config_hash THEN imap_connections.revision ELSE excluded.revision END,
		updated_at=excluded.updated_at`, subject, accountID, c.Address, c.Username, c.Password, c.TLS, c.Mailbox, c.PollSeconds, c.RecheckSeconds, c.MaxMessages, c.Hash, c.Revision, now)
	return err
}

func verifyIMAPLogin(ctx context.Context, c PushIMAPProof) error {
	host, _, _ := net.SplitHostPort(c.Address)
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	verifyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dialAddress, err := publicIMAPDialAddress(verifyCtx, c.Address)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	if c.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(verifyCtx, "tcp", dialAddress)
	} else {
		conn, err = dialer.DialContext(verifyCtx, "tcp", dialAddress)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(verifyCtx, func() { _ = conn.Close() })
	defer stop()
	options := &imapclient.Options{TLSConfig: tlsConfig}
	var client *imapclient.Client
	if c.TLS == "starttls" {
		client, err = imapclient.NewStartTLS(conn, options)
	} else {
		client = imapclient.New(conn, options)
	}
	if err != nil {
		return err
	}
	defer client.Close()
	if err = client.WaitGreeting(); err != nil {
		return err
	}
	if err = client.Login(c.Username, c.Password).Wait(); err != nil {
		return err
	}
	_, err = client.Select(c.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	return err
}

func publicIMAPDialAddress(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, candidate := range addresses {
		ip := candidate.IP
		if ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !carrierGradeNAT.Contains(ip) {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", errors.New("IMAP host has no public address")
}
