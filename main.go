package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/iveteran/OAuth2ACF/controller"
	"github.com/iveteran/OAuth2ACF/model"
	"github.com/iveteran/OAuth2ACF/service"

	_ "github.com/mattn/go-sqlite3"
)

var Version = "dev"

// 自定义ResponseWriter用于捕获状态码
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// 日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建一个自定义的ResponseWriter来捕获状态码
		lrw := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// 执行下一个处理器
		next.ServeHTTP(lrw, r)

		// 记录日志
		log.Printf("%s %s %d %v %s",
			r.Method,
			r.URL.Path,
			lrw.statusCode,
			time.Since(start),
			r.RemoteAddr,
		)
	})
}

func main() {
	databasePath := strings.TrimSpace(os.Getenv("OAUTH2ACF_DATABASE_PATH"))
	if databasePath == "" {
		databasePath = "./oauth2.db"
	}
	db, err := sql.Open("sqlite3", databasePath+"?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	authService := &service.AuthService{DB: db}
	authController := &controller.AuthController{Service: authService}

	if err = authService.InitDB(); err != nil {
		log.Fatal(err)
	}
	if clientsFile := strings.TrimSpace(os.Getenv("OAUTH2ACF_CLIENTS_FILE")); clientsFile != "" {
		importCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = model.ImportOAuthClients(importCtx, db, clientsFile)
		cancel()
		if err != nil {
			log.Fatal(err)
		}
		log.Print("OAuth client configuration imported")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if db.PingContext(ctx) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"database unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("/authorize", authController.Authorize)
	mux.HandleFunc("/callback", authController.Callback)
	mux.HandleFunc("/get_token", authController.GetToken)
	pushController, err := configuredPushController(db)
	if err != nil {
		log.Fatal(err)
	}
	if pushController != nil {
		mux.HandleFunc("/v1/push/token", pushController.Token)
		mux.HandleFunc("/v1/push/session", pushController.Session)
		mux.HandleFunc("/internal/v1/provider-connections", pushController.Connections)
		mux.HandleFunc("/internal/v1/provider-token", pushController.ProviderToken)
		mux.HandleFunc("/internal/v1/imap-connections", pushController.IMAPConnections)
		mux.HandleFunc("/internal/v1/imap-password", pushController.IMAPPassword)
	}

	// 使用日志中间件包装处理器
	loggedMux := loggingMiddleware(mux)

	listenAddress := os.Getenv("OAUTH2ACF_LISTEN_ADDRESS")
	if listenAddress == "" {
		listenAddress = ":9090"
	}

	log.Printf("Version: %s\n", Version)
	log.Printf("Server listening at %s\n", listenAddress)
	log.Printf("NOTE: Override listening address with the OAUTH2ACF_LISTEN_ADDRESS environment variable if needed.")

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           loggedMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	select {
	case <-signalCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err = server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown failed: %v", err)
		}
	case err = <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}
}

func configuredPushController(db *sql.DB) (*controller.PushController, error) {
	keyFile := strings.TrimSpace(os.Getenv("OAUTH2ACF_PUSH_SIGNING_KEY_FILE"))
	issuer := strings.TrimSpace(os.Getenv("OAUTH2ACF_PUSH_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("OAUTH2ACF_PUSH_AUDIENCE"))
	brokerFile := strings.TrimSpace(os.Getenv("OAUTH2ACF_PUSH_BROKER_KEY_FILE"))
	if keyFile == "" && issuer == "" && audience == "" && brokerFile == "" {
		log.Print("Push account endpoints disabled")
		return nil, nil
	}
	if keyFile == "" || issuer == "" || audience == "" || brokerFile == "" {
		return nil, errors.New("all OAUTH2ACF push configuration fields are required")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.New("push signing key unavailable")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid push signing key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid push signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("push signing key must be Ed25519")
	}
	brokerBytes, err := os.ReadFile(brokerFile)
	if err != nil {
		return nil, errors.New("push broker key unavailable")
	}
	brokerKey := strings.TrimSpace(string(brokerBytes))
	if len(brokerKey) < 32 {
		return nil, errors.New("push broker key must contain at least 32 characters")
	}
	pushService := &service.PushService{DB: db, SigningKey: key, Issuer: issuer, Audience: audience}
	if err = pushService.InitDB(); err != nil {
		return nil, err
	}
	return &controller.PushController{Service: pushService, BrokerKey: brokerKey}, nil
}
