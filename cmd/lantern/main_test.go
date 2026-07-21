package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/erniebrodeur/lantern/internal/config"
)

func TestDefaultDatabasePathUsesSUDOUser(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_USER", account.Username)
	path, owner, err := config.DefaultDatabase()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if path != filepath.Join(account.HomeDir, ".lantern", "lantern.db") || owner == nil || owner.UID != uid || owner.GID != gid {
		t.Fatalf("unexpected sudo database identity: %q %#v", path, owner)
	}
}

func TestRunContextReportsSetupAndListenErrors(t *testing.T) {
	t.Setenv("SUDO_USER", "lantern-user-that-does-not-exist")
	if err := runContext(context.Background()); err == nil {
		t.Fatal("runContext accepted an unknown SUDO_USER")
	}

	t.Setenv("SUDO_USER", "")
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANTERN_DB_PATH", filepath.Join(parent, "lantern.db"))
	if err := runContext(context.Background()); err == nil {
		t.Fatal("runContext accepted an invalid database path")
	}

	t.Setenv("LANTERN_DB_PATH", filepath.Join(t.TempDir(), "lantern.db"))
	t.Setenv("LANTERN_ADDR", "bad-address")
	originalListen := listenAndServe
	listenAndServe = func(*http.Server) error { return errors.New("listen failed") }
	defer func() { listenAndServe = originalListen }()
	if err := runContext(context.Background()); err == nil || err.Error() != "listen failed" {
		t.Fatalf("unexpected listen error: %v", err)
	}
}

func TestRunContextShutsDownWhenCancelled(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("LANTERN_DB_PATH", filepath.Join(t.TempDir(), "lantern.db"))
	t.Setenv("LANTERN_ADDR", "127.0.0.1:0")
	originalListen, originalShutdown := listenAndServe, shutdownServer
	stopped := make(chan struct{})
	listenAndServe = func(*http.Server) error {
		<-stopped
		return http.ErrServerClosed
	}
	shutdownServer = func(*http.Server, context.Context) error {
		close(stopped)
		return nil
	}
	defer func() {
		listenAndServe, shutdownServer = originalListen, originalShutdown
	}()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if err := runContext(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRunAndVersionMain(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("LANTERN_DB_PATH", filepath.Join(t.TempDir(), "lantern.db"))
	originalListen := listenAndServe
	listenAndServe = func(*http.Server) error { return http.ErrServerClosed }
	defer func() { listenAndServe = originalListen }()
	if err := run(); err != nil {
		t.Fatal(err)
	}
	originalArgs := os.Args
	os.Args = []string{"lantern", "--version"}
	defer func() { os.Args = originalArgs }()
	main()
}

func TestRunContextReturnsListenerErrorDuringShutdown(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("LANTERN_DB_PATH", filepath.Join(t.TempDir(), "lantern.db"))
	originalListen, originalShutdown := listenAndServe, shutdownServer
	stopped := make(chan struct{})
	listenAndServe = func(*http.Server) error {
		<-stopped
		return errors.New("late listen failure")
	}
	shutdownServer = func(*http.Server, context.Context) error {
		close(stopped)
		return nil
	}
	defer func() { listenAndServe, shutdownServer = originalListen, originalShutdown }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runContext(ctx); err == nil || err.Error() != "late listen failure" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultDatabasePathRejectsUnknownSUDOUser(t *testing.T) {
	t.Setenv("SUDO_USER", "lantern-user-that-does-not-exist")
	if _, _, err := config.DefaultDatabase(); err == nil {
		t.Fatal("expected an unknown SUDO_USER to fail")
	}
}
