package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/erniebrodeur/lantern/internal/store"
)

// Database describes the database path and, for a sudo launch, the invoking
// user's ownership. Both Lantern entry points use this configuration.
type Database struct {
	Path  string
	Owner *store.FileOwner
}

func DatabaseFromEnvironment() (Database, error) {
	path, owner, err := DefaultDatabase()
	if err != nil {
		return Database{}, err
	}
	return Database{Path: EnvOrDefault("LANTERN_DB_PATH", path), Owner: owner}, nil
}

func DefaultDatabase() (string, *store.FileOwner, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		account, err := user.Lookup(sudoUser)
		if err != nil {
			return "", nil, fmt.Errorf("resolve SUDO_USER %q: %w", sudoUser, err)
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil {
			return "", nil, fmt.Errorf("parse SUDO_USER uid: %w", err)
		}
		gid, err := strconv.Atoi(account.Gid)
		if err != nil {
			return "", nil, fmt.Errorf("parse SUDO_USER gid: %w", err)
		}
		return filepath.Join(account.HomeDir, ".lantern", "lantern.db"), &store.FileOwner{UID: uid, GID: gid}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(home, ".lantern", "lantern.db"), nil, nil
}

func EnvOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func OpenDatabase(configuration Database) (*store.SQLite, error) {
	if configuration.Owner != nil {
		return store.OpenOwned(configuration.Path, *configuration.Owner)
	}
	return store.Open(configuration.Path)
}
