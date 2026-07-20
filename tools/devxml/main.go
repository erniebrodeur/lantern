// Command devxml loads the temporary development XML capture into an isolated
// Lantern database. It is development scaffolding for Slice 3, not a product
// import interface.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/erniebrodeur/lantern/internal/scans"
	"github.com/erniebrodeur/lantern/internal/store"
)

const maximumFixtureBytes = 50 * 1024 * 1024

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	xmlPath := flag.String("xml", "dev.xml", "Nmap XML fixture")
	databasePath := flag.String("db", "dev.db", "development SQLite database")
	target := flag.String("target", "203.0.113.0/24", "declared fixture target")
	flag.Parse()

	normalizedTarget, err := scans.ValidateTarget(*target)
	if err != nil {
		return err
	}
	info, err := os.Stat(*xmlPath)
	if err != nil {
		return err
	}
	if info.Size() > maximumFixtureBytes {
		return fmt.Errorf("fixture exceeds %d bytes", maximumFixtureBytes)
	}
	content, err := os.ReadFile(*xmlPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(content)
	identifier := "dev-" + hex.EncodeToString(digest[:8])

	database, err := store.Open(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	ctx := context.Background()
	if existing, err := database.Get(ctx, identifier); err == nil {
		fmt.Printf("fixture already loaded: %s (%s)\n", existing.ID, existing.Target)
		return nil
	} else if !scans.IsNotFound(err) {
		return err
	}

	scan := scans.Scan{
		ID: identifier, Target: normalizedTarget, Status: scans.StatusRunning,
		Arguments: []string{"fixture", filepath.Base(*xmlPath)}, CreatedAt: time.Now().UTC(),
	}
	if err := database.Create(ctx, scan); err != nil {
		return err
	}
	result, err := scans.ParseNmapXMLIncremental(bytes.NewReader(content), nil, func(host scans.HostObservation) error {
		_, err := database.SaveHost(ctx, identifier, host)
		return err
	})
	if err != nil {
		_ = database.Finish(ctx, identifier, scans.StatusFailed, time.Now().UTC(), nil, err.Error())
		return err
	}
	if err := database.SaveSummary(ctx, identifier, result); err != nil {
		return err
	}
	exitCode := 0
	if err := database.Finish(ctx, identifier, scans.StatusCompleted, time.Now().UTC(), &exitCode, ""); err != nil {
		return err
	}
	fmt.Printf("loaded %s: %d up, %d down, %d total\n", identifier, result.HostsUp, result.HostsDown, result.HostsTotal)
	return nil
}
