package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/erniebrodeur/lantern/internal/config"
	"github.com/erniebrodeur/lantern/internal/httpapi"
	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/version"
)

const shutdownTimeout = 5 * time.Second

var (
	listenAndServe = func(server *http.Server) error { return server.ListenAndServe() }
	shutdownServer = func(server *http.Server, ctx context.Context) error { return server.Shutdown(ctx) }
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println(version.Value)
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (resultErr error) {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(signalContext)
}

func runContext(signalContext context.Context) (resultErr error) {
	address := config.EnvOrDefault("LANTERN_ADDR", "127.0.0.1:1414")
	databaseConfig, err := config.DatabaseFromEnvironment()
	if err != nil {
		return err
	}
	nmapPath := config.EnvOrDefault("LANTERN_NMAP_PATH", "nmap")

	database, err := config.OpenDatabase(databaseConfig)
	if err != nil {
		return err
	}
	defer func() {
		if err := database.Close(); resultErr == nil && err != nil {
			resultErr = err
		}
	}()

	manager, err := scans.NewManager(database, nmapPath)
	if err != nil {
		return err
	}
	router, err := httpapi.NewRouter(manager)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              address,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Lantern API listening on http://%s", address)
		serverErrors <- listenAndServe(server)
	}()

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-signalContext.Done():
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	manager.Shutdown(shutdownContext)
	if err := shutdownServer(server, shutdownContext); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
