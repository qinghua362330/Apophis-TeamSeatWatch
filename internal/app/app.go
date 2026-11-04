package app

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/egress"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/migrations"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/mothersecret"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/runtime"
)

// DiagnosticError carries a stable host-command diagnostic code without exposing secrets.
type DiagnosticError struct {
	code string
}

func (e *DiagnosticError) Error() string { return e.code }

// ErrorCode maps runtime errors to the stable diagnostic surfaced by the CLI.
func ErrorCode(err error) string {
	var diagnostic *DiagnosticError
	if errors.As(err, &diagnostic) {
		return diagnostic.code
	}
	return "runtime_failure"
}

func diagnostic(code string) error {
	return &DiagnosticError{code: code}
}

const (
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 5 * time.Second
	requestTimeout    = 5 * time.Second
	connectionTimeout = 3 * time.Second
	idleTimeout       = 30 * time.Second
	privateClientName = "gateway"
)

// Run dispatches the selected deployment role or explicit host-only Owner command.
func Run(ctx context.Context, role string, getenv func(string) string, logger *slog.Logger) error {
	switch role {
	case "control":
		return runControl(ctx, getenv, logger)
	case "gateway":
		return runGateway(ctx, getenv, logger)
	case "migrate":
		return runMigrate(ctx, getenv)
	case "owner-create", "owner-reset":
		return runOwnerCommand(ctx, role, getenv)
	default:
		return diagnostic("invalid_command")
	}
}

func runControl(ctx context.Context, getenv func(string) string, logger *slog.Logger) error {
	dsn, err := required(getenv, databaseURLEnv)
	if err != nil {
		return err
	}
	keyRingFile, err := required(getenv, totpKeyringFileEnv)
	if err != nil {
		return err
	}
	keyRing, err := auth.LoadKeyRingFile(keyRingFile)
	if err != nil {
		return fmt.Errorf("invalid TOTP key ring: %w", err)
	}
	platformBaseURL, err := required(getenv, platformBaseURLEnv)
	if err != nil {
		return err
	}
	keyVersion, key := keyRing.Current()
	// Routes are restored from Owner-managed database settings before listeners
	// open. The empty admission pool remains closed until the saved mode is loaded.
	egressConfig := egress.Config{Mode: egress.ModeRequired, ReachabilityURL: platformBaseURL, IPEchoURL: "https://api.ipify.org/", HMACKey: key[:], HMACKeyVersion: fmt.Sprintf("%d", keyVersion), ProbeConcurrency: 5}
	if target, parseErr := url.Parse(platformBaseURL); parseErr == nil && target.Scheme == "https" && target.Host == "chatgpt.com" {
		egressConfig.ReachabilityProbe = platform.ProbeBrowserReachability
	}
	router, err := egress.New(egressConfig)
	if err != nil {
		return diagnostic(egress.ErrorCode(err))
	}
	admission, admissionErr := router.Admit(ctx)
	if admissionErr != nil && ctx.Err() != nil {
		router.CloseIdleConnections()
		return ctx.Err()
	}
	defer router.CloseIdleConnections()
	leases, err := egress.NewLeaseManager(router, admission)
	if err != nil {
		return err
	}
	egressManager := egress.NewManager(leases, router.Status(admission))
	publicAddress, err := required(getenv, controlListenEnv)
	if err != nil {
		return err
	}
	privateAddress, err := required(getenv, privateListenEnv)
	if err != nil {
		return err
	}
	if err := validatePrivateAddress(privateAddress); err != nil {
		return err
	}
	staticDir, err := required(getenv, ownerStaticDirEnv)
	if err != nil {
		return err
	}
	origins, err := auth.ParseOriginPolicy(getenv(ownerOriginsEnv))
	if err != nil {
		return diagnostic("owner_origin_allowlist_invalid")
	}
	caFile, err := required(getenv, tlsCAFileEnv)
	if err != nil {
		return err
	}
	certFile, err := required(getenv, tlsCertFileEnv)
	if err != nil {
		return err
	}
	keyFile, err := required(getenv, tlsKeyFileEnv)
	if err != nil {
		return err
	}
	privateTLS, err := runtime.LoadServerTLS(runtime.ServerTLSConfig{
		CAFile: caFile, CertFile: certFile, KeyFile: keyFile,
		AllowedClientCommonNames: []string{privateClientName},
	})
	if err != nil {
		return fmt.Errorf("invalid private TLS configuration: %w", err)
	}
	handlers, err := runtime.NewControlHandlers(runtime.ControlConfig{
		DatabaseURL: dsn, StaticDir: staticDir,
		Context: ctx, PlatformClients: router, Egress: egressManager,
		PlatformBaseURL:  platformBaseURL,
		TOTPKeyRingFile:  keyRingFile,
		OwnerOrigins:     origins,
		CPAWebhookSecret: getenv(cpaWebhookSecretEnv),
		CPAManagementURL: getenv(cpaManagementURLEnv),
		CPAManagementKey: getenv(cpaManagementKeyEnv),
	})
	if err != nil {
		return err
	}
	defer handlers.Close()
	public, err := net.Listen("tcp", publicAddress)
	if err != nil {
		return err
	}
	private, err := net.Listen("tcp", privateAddress)
	if err != nil {
		_ = public.Close()
		return err
	}
	return serve(ctx, logger, []listener{
		{socket: public, server: newServer(runtime.NewRequestMiddleware(logger)(handlers.Public))},
		{socket: tls.NewListener(private, privateTLS), server: newServer(runtime.NewRequestMiddleware(logger)(handlers.Private))},
	})
}

func runGateway(ctx context.Context, getenv func(string) string, logger *slog.Logger) error {
	for _, secret := range []string{
		databaseURLEnv, platformCredentialsEnv, platformBaseURLEnv,
		totpKeyringFileEnv, ownerLoginEnv, ownerPasswordEnv, ownerOriginsEnv,
	} {
		if getenv(secret) != "" {
			return diagnostic("gateway_forbidden_secret")
		}
	}
	address, err := required(getenv, gatewayListenEnv)
	if err != nil {
		return err
	}
	endpoint, err := required(getenv, controlPrivateURLEnv)
	if err != nil {
		return err
	}
	staticDir, err := required(getenv, publicStaticDirEnv)
	if err != nil {
		return err
	}
	caFile, err := required(getenv, tlsCAFileEnv)
	if err != nil {
		return err
	}
	certFile, err := required(getenv, tlsCertFileEnv)
	if err != nil {
		return err
	}
	keyFile, err := required(getenv, tlsKeyFileEnv)
	if err != nil {
		return err
	}
	serverName, err := required(getenv, controlServerNameEnv)
	if err != nil {
		return err
	}
	clientTLS, err := runtime.LoadClientTLS(runtime.ClientTLSConfig{
		CAFile: caFile, CertFile: certFile, KeyFile: keyFile, ServerName: serverName,
	})
	if err != nil {
		return fmt.Errorf("invalid gateway TLS configuration: %w", err)
	}
	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       clientTLS,
			DialContext:           (&net.Dialer{Timeout: connectionTimeout}).DialContext,
			TLSHandshakeTimeout:   connectionTimeout,
			ResponseHeaderTimeout: requestTimeout,
			IdleConnTimeout:       idleTimeout,
		},
	}
	handler, closeHandler, err := runtime.NewGatewayHandler(runtime.GatewayConfig{
		ControlURL: endpoint, ProbeClient: client, StaticDir: staticDir,
	})
	if err != nil {
		return err
	}
	defer closeHandler()
	socket, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return serve(ctx, logger, []listener{{socket: socket, server: newServer(runtime.NewRequestMiddleware(logger)(handler))}})
}

func runMigrate(ctx context.Context, getenv func(string) string) error {
	dsn, err := required(getenv, databaseURLEnv)
	if err != nil {
		return err
	}
	keyFile, err := required(getenv, totpKeyringFileEnv)
	if err != nil {
		return err
	}
	ring, err := auth.LoadKeyRingFile(keyFile)
	if err != nil {
		return fmt.Errorf("invalid mother material key ring: %w", err)
	}
	connection, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.PingContext(ctx); err != nil {
		return err
	}
	if err := migrations.Apply(ctx, connection); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	return mothersecret.Migrate(ctx, pool, ring)
}

func required(getenv func(string) string, name string) (string, error) {
	value := getenv(name)
	if value == "" {
		return "", diagnostic("config_missing")
	}
	return value, nil
}

func validatePrivateAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("private listener requires an explicit host and port")
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		return errors.New("private listener must bind to a loopback or private IP")
	}
	return nil
}

type listener struct {
	socket net.Listener
	server *http.Server
}

func newServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: readHeaderTimeout, IdleTimeout: idleTimeout}
}

func serve(ctx context.Context, logger *slog.Logger, listeners []listener) error {
	results := make(chan error, len(listeners))
	for _, item := range listeners {
		go func(item listener) {
			err := item.server.Serve(item.socket)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			results <- err
		}(item)
	}
	var result error
	select {
	case <-ctx.Done():
		logger.Info("shutdown_requested")
	case result = <-results:
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, item := range listeners {
		if err := item.server.Shutdown(shutdownContext); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
