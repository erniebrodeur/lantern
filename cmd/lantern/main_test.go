package main

import (
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

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

func TestDefaultDatabasePathRejectsUnknownSUDOUser(t *testing.T) {
	t.Setenv("SUDO_USER", "lantern-user-that-does-not-exist")
	if _, _, err := config.DefaultDatabase(); err == nil {
		t.Fatal("expected an unknown SUDO_USER to fail")
	}
}
