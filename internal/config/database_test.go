package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/erniebrodeur/lantern/internal/store"
)

func TestDatabaseEnvironmentAndDefaults(t *testing.T) {
	t.Run("fallback and override", func(t *testing.T) {
		t.Setenv("LANTERN_TEST_VALUE", "")
		if got := EnvOrDefault("LANTERN_TEST_VALUE", "fallback"); got != "fallback" {
			t.Fatalf("fallback = %q", got)
		}
		t.Setenv("LANTERN_TEST_VALUE", "configured")
		if got := EnvOrDefault("LANTERN_TEST_VALUE", "fallback"); got != "configured" {
			t.Fatalf("override = %q", got)
		}
	})

	t.Run("normal user", func(t *testing.T) {
		t.Setenv("SUDO_USER", "")
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		path, owner, err := DefaultDatabase()
		if err != nil {
			t.Fatal(err)
		}
		if path != filepath.Join(home, ".lantern", "lantern.db") || owner != nil {
			t.Fatalf("default = %q %#v", path, owner)
		}
	})

	t.Run("sudo user", func(t *testing.T) {
		account, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("SUDO_USER", account.Username)
		path, owner, err := DefaultDatabase()
		if err != nil {
			t.Fatal(err)
		}
		uid, _ := strconv.Atoi(account.Uid)
		gid, _ := strconv.Atoi(account.Gid)
		if path != filepath.Join(account.HomeDir, ".lantern", "lantern.db") || owner == nil || owner.UID != uid || owner.GID != gid {
			t.Fatalf("sudo default = %q %#v", path, owner)
		}
	})

	t.Run("unknown sudo user", func(t *testing.T) {
		t.Setenv("SUDO_USER", "lantern-user-that-does-not-exist")
		if _, _, err := DefaultDatabase(); err == nil {
			t.Fatal("expected unknown user error")
		}
	})

	t.Run("database override", func(t *testing.T) {
		t.Setenv("SUDO_USER", "")
		want := filepath.Join(t.TempDir(), "custom.db")
		t.Setenv("LANTERN_DB_PATH", want)
		configuration, err := DatabaseFromEnvironment()
		if err != nil || configuration.Path != want || configuration.Owner != nil {
			t.Fatalf("configuration = %#v, %v", configuration, err)
		}
	})
}

func TestOpenDatabaseConfigurations(t *testing.T) {
	for _, test := range []struct {
		name  string
		owner *store.FileOwner
	}{
		{name: "ordinary"},
		{name: "owned", owner: &store.FileOwner{UID: os.Getuid(), GID: os.Getgid()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nested", "lantern.db")
			database, err := OpenDatabase(Database{Path: path, Owner: test.owner})
			if err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("database file: %#v, %v", info, err)
			}
		})
	}
}
