package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/go-tfe"
)

// This is a self-signed certificate to satisfy the connection from UniFi to
// this service. There's no security risk here.
var (
	//go:embed tls/cert.pem
	tlsCert []byte

	//go:embed tls/key.pem
	tlsKey []byte
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{}))

	if err := run(context.Background(), logger); err != nil {
		logger.Error("startup finished", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	privBlock, _ := pem.Decode(tlsKey)
	privateKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed parsing tls private key: %w", err)
	}

	pubBlock, _ := pem.Decode(tlsCert)

	unifiUsername := os.Getenv("UNIFI_USERNAME")
	if unifiUsername == "" {
		return errors.New("UNIFI_USERNAME must be provided")
	}

	unifiPassword := os.Getenv("UNIFI_PASSWORD")
	if unifiPassword == "" {
		return errors.New("UNIFI_PASSWORD must be provided")
	}

	terraformCloudApiToken := os.Getenv("TERRAFORM_CLOUD_API_TOKEN")
	if terraformCloudApiToken == "" {
		return errors.New("TERRAFORM_CLOUD_API_TOKEN must be provided")
	}

	terraformCloudAddress := os.Getenv("TERRAFORM_CLOUD_ADDRESS")
	if terraformCloudAddress == "" {
		return errors.New("TERRAFORM_CLOUD_ADDRESS must be provided")
	}

	terraformCloudClient, err := tfe.NewClient(&tfe.Config{
		Address: terraformCloudAddress,
		Token:   terraformCloudApiToken,
	})

	if err != nil {
		return fmt.Errorf("failed creating terraform cloud client: %w", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /nic/update", func(w http.ResponseWriter, r *http.Request) {
		username, password, hasAuth := r.BasicAuth()
		if !hasAuth {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if username != unifiUsername || password != unifiPassword {
			respond(w, "badauth")
			return
		}

		ip := r.URL.Query().Get("myip")
		if ip == "" {
			respond(w, "911")
			return
		}

		if _, err := terraformCloudClient.Variables.Update(r.Context(), "ws-KidBzbXUjLSXKYgH", "var-ovgRSmpM1gLBgywH", tfe.VariableUpdateOptions{
			Value: tfe.String(ip),
		}); err != nil {
			respond(w, "911")
			return
		}

		if _, err := terraformCloudClient.Runs.Create(r.Context(), tfe.RunCreateOptions{
			Message: tfe.String("Triggered via dynamic dns."),
			Workspace: &tfe.Workspace{
				ID: "ws-KidBzbXUjLSXKYgH",
			},
			AutoApply: tfe.Bool(true),
		}); err != nil {
			respond(w, "911")
			return
		}

		logger.Info("success", "myip", ip)
		respond(w, fmt.Sprintf("good %s", ip))
	})

	srv := http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{pubBlock.Bytes},
					PrivateKey:  privateKey,
				},
			},
		},
		Handler: mux,
	}

	logger.Info("starting http server", "addr", srv.Addr)

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT)
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		// TLS configuration is provided in the http.Server. UniFi expects TLS but it
		// doesn't verify the certificates so we use self-signed certificates.
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down gracefully", "reason", ctx.Err())
		shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCtxCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutting down forcefully", "error", err)
			return srv.Close()
		}
	case err := <-errCh:
		return err
	}

	return nil
}

// respond responds with 200 OK with some string body because that's how the
// DynDNS protocol likes it.
func respond(w http.ResponseWriter, body string) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
