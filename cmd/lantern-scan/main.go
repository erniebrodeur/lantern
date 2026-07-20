// Command lantern-scan runs an Nmap range scan through Lantern's scan manager
// and persists the result in the same database used by the server.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/erniebrodeur/lantern/internal/config"
	"github.com/erniebrodeur/lantern/internal/scans"
)

const usage = `usage: lantern-scan <discovery|quick|standard|deep> <CIDR> [--args <nmap arguments...>]

Examples:
  lantern-scan quick 192.168.1.0/24
  lantern-scan deep 10.0.0.0/24 --args -Pn --min-rate 1000

Everything after --args is passed to Nmap as additional arguments. Lantern
still owns the target, XML output, and progress arguments.`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) (resultErr error) {
	request, err := parseRequest(arguments)
	if err != nil {
		return err
	}
	databaseConfig, err := config.DatabaseFromEnvironment()
	if err != nil {
		return err
	}
	database, err := config.OpenDatabase(databaseConfig)
	if err != nil {
		return err
	}
	defer func() {
		if err := database.Close(); resultErr == nil && err != nil {
			resultErr = err
		}
	}()

	manager, err := scans.NewManager(database, config.EnvOrDefault("LANTERN_NMAP_PATH", "nmap"))
	if err != nil {
		return err
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(shutdownContext)
	}()
	scan, err := manager.StartRequest(context.Background(), request)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "scan %s queued: %s (%s)\n", scan.ID, scan.Target, strings.TrimPrefix(scan.ProfileID, "builtin:"))

	events, unsubscribe := manager.Subscribe(scan.ID)
	defer unsubscribe()
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		current, err := manager.Get(context.Background(), scan.ID)
		if err != nil {
			return err
		}
		if terminal(current.Status) {
			return reportResult(stdout, current)
		}
		select {
		case event := <-events:
			if event.Type == "output" {
				writer := stdout
				if event.Stream == "stderr" {
					writer = stderr
				}
				fmt.Fprint(writer, event.Text)
			}
		case <-signalContext.Done():
			_ = manager.Cancel(scan.ID)
			return signalContext.Err()
		}
	}
}

func parseRequest(arguments []string) (scans.ScanRequest, error) {
	if len(arguments) < 2 {
		return scans.ScanRequest{}, errors.New(usage)
	}
	mode := strings.ToLower(arguments[0])
	if _, ok := scans.BuiltInProfile("builtin:" + mode); !ok {
		return scans.ScanRequest{}, fmt.Errorf("unknown scan mode %q; expected discovery, quick, standard, or deep", arguments[0])
	}
	request := scans.ScanRequest{Target: arguments[1], ProfileID: "builtin:" + mode}
	if len(arguments) == 2 {
		return request, nil
	}
	if arguments[2] != "--args" {
		return scans.ScanRequest{}, fmt.Errorf("unexpected argument %q; Nmap arguments must follow --args", arguments[2])
	}
	if len(arguments) == 3 {
		return scans.ScanRequest{}, errors.New("--args requires at least one Nmap argument")
	}
	request.AdditionalArguments = append([]string(nil), arguments[3:]...)
	return request, nil
}

func terminal(status scans.Status) bool {
	return status == scans.StatusCompleted || status == scans.StatusFailed || status == scans.StatusCancelled || status == scans.StatusInterrupted
}

func reportResult(output io.Writer, scan scans.Scan) error {
	fmt.Fprintf(output, "scan %s %s: %d up, %d down, %d total\n", scan.ID, scan.Status, scan.HostsUp, scan.HostsDown, scan.HostsTotal)
	if scan.Status != scans.StatusCompleted {
		if scan.Error != "" {
			return errors.New(scan.Error)
		}
		return fmt.Errorf("scan ended with status %s", scan.Status)
	}
	return nil
}
