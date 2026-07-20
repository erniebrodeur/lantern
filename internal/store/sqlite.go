package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/erniebrodeur/lantern/internal/providers"
	"github.com/erniebrodeur/lantern/internal/scans"
	_ "modernc.org/sqlite"
)

const timestampFormat = time.RFC3339Nano

type SQLite struct {
	database *sql.DB
	path     string
	owner    *FileOwner
}

func Open(path string) (*SQLite, error) {
	return open(path, nil)
}

type FileOwner struct {
	UID int
	GID int
}

func OpenOwned(path string, owner FileOwner) (*SQLite, error) {
	return open(path, &owner)
}

func open(path string, owner *FileOwner) (*SQLite, error) {
	if err := prepareDatabasePath(path, owner); err != nil {
		return nil, err
	}
	if directory := filepath.Dir(path); directory != "." {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	database.SetMaxOpenConns(1)
	store := &SQLite{database: database, path: path, owner: owner}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := database.Exec(statement); err != nil {
			closeErr := database.Close()
			ownershipErr := store.repairOwnership()
			return nil, errors.Join(fmt.Errorf("configure sqlite: %w", err), closeErr, ownershipErr)
		}
	}
	if err := store.migrate(context.Background()); err != nil {
		closeErr := database.Close()
		ownershipErr := store.repairOwnership()
		return nil, errors.Join(err, closeErr, ownershipErr)
	}
	if err := store.repairOwnership(); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLite) Close() error {
	closeErr := s.database.Close()
	ownershipErr := s.repairOwnership()
	return errors.Join(closeErr, ownershipErr)
}

func prepareDatabasePath(path string, owner *FileOwner) error {
	directory := filepath.Dir(path)
	if info, err := os.Lstat(directory); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("database directory cannot be a symbolic link")
		}
		if !info.IsDir() {
			return fmt.Errorf("database directory is not a directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect database directory: %w", err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if info, err := os.Lstat(candidate); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("SQLite file %s cannot be a symbolic link", filepath.Base(candidate))
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("SQLite file %s is not a regular file", filepath.Base(candidate))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect SQLite file %s: %w", filepath.Base(candidate), err)
		}
	}
	if owner != nil && directory != "." {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}
		if err := os.Chown(directory, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("set database directory ownership: %w", err)
		}
	}
	return nil
}

func (s *SQLite) repairOwnership() error {
	if s.owner == nil {
		return nil
	}
	for _, path := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite file ownership: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("SQLite file %s is not a regular file", filepath.Base(path))
		}
		if err := os.Lchown(path, s.owner.UID, s.owner.GID); err != nil {
			return fmt.Errorf("set %s ownership: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func (s *SQLite) Create(ctx context.Context, scan scans.Scan) error {
	arguments, err := json.Marshal(scan.Arguments)
	if err != nil {
		return err
	}
	_, err = s.database.ExecContext(ctx, `
		INSERT INTO scan_runs (id, target, profile_id, os_detection, status, arguments_json, created_at, output)
		VALUES (?, ?, ?, ?, ?, ?, ?, '')
	`, scan.ID, scan.Target, scan.ProfileID, scan.OSDetection, scan.Status, string(arguments), formatTime(scan.CreatedAt))
	return err
}

func (s *SQLite) ListProfiles(ctx context.Context) ([]scans.Profile, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT id, argument_text, arguments_json, created_at, updated_at
		FROM scan_profiles ORDER BY updated_at DESC, id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	profiles := make([]scans.Profile, 0)
	for rows.Next() {
		profile, err := readProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, rows.Err()
}

func (s *SQLite) GetProfile(ctx context.Context, identifier string) (scans.Profile, error) {
	profile, err := readProfile(s.database.QueryRowContext(ctx, `
		SELECT id, argument_text, arguments_json, created_at, updated_at
		FROM scan_profiles WHERE id = ?
	`, identifier))
	if errors.Is(err, sql.ErrNoRows) {
		return scans.Profile{}, scans.ErrNotFound
	}
	return profile, err
}

func (s *SQLite) CreateProfile(ctx context.Context, profile scans.Profile) error {
	if profile.CreatedAt == nil || profile.UpdatedAt == nil {
		return fmt.Errorf("profile timestamps are required")
	}
	arguments, err := json.Marshal(profile.Arguments)
	if err != nil {
		return err
	}
	_, err = s.database.ExecContext(ctx, `
		INSERT INTO scan_profiles (id, argument_text, arguments_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, profile.ID, profile.ArgumentText, string(arguments), formatTime(*profile.CreatedAt), formatTime(*profile.UpdatedAt))
	return err
}

func (s *SQLite) UpdateProfile(ctx context.Context, profile scans.Profile) error {
	if profile.UpdatedAt == nil {
		return fmt.Errorf("profile update timestamp is required")
	}
	arguments, err := json.Marshal(profile.Arguments)
	if err != nil {
		return err
	}
	result, err := s.database.ExecContext(ctx, `
		UPDATE scan_profiles SET argument_text = ?, arguments_json = ?, updated_at = ? WHERE id = ?
	`, profile.ArgumentText, string(arguments), formatTime(*profile.UpdatedAt), profile.ID)
	return checkUpdated(result, err)
}

func (s *SQLite) DeleteProfile(ctx context.Context, identifier string) error {
	result, err := s.database.ExecContext(ctx, "DELETE FROM scan_profiles WHERE id = ?", identifier)
	return checkUpdated(result, err)
}

func (s *SQLite) List(ctx context.Context) ([]scans.Scan, error) {
	rows, err := s.database.QueryContext(ctx, selectAllScans)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]scans.Scan, 0)
	for rows.Next() {
		scan, err := readScan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, scan)
	}
	return result, rows.Err()
}

func (s *SQLite) Get(ctx context.Context, identifier string) (scans.Scan, error) {
	scan, err := readScan(s.database.QueryRowContext(ctx, selectScan+" WHERE id = ?", identifier))
	if errors.Is(err, sql.ErrNoRows) {
		return scans.Scan{}, scans.ErrNotFound
	}
	return scan, err
}

func (s *SQLite) Delete(ctx context.Context, identifier string) error {
	result, err := s.database.ExecContext(ctx, "DELETE FROM scan_runs WHERE id = ?", identifier)
	return checkUpdated(result, err)
}

func (s *SQLite) MarkStarted(ctx context.Context, identifier string, startedAt time.Time) error {
	result, err := s.database.ExecContext(ctx, `
		UPDATE scan_runs SET status = ?, started_at = ? WHERE id = ?
	`, scans.StatusRunning, formatTime(startedAt), identifier)
	return checkUpdated(result, err)
}

func (s *SQLite) AppendOutput(ctx context.Context, identifier, output string) error {
	result, err := s.database.ExecContext(ctx, `
		UPDATE scan_runs SET output = output || ? WHERE id = ?
	`, output, identifier)
	return checkUpdated(result, err)
}

func (s *SQLite) Finish(ctx context.Context, identifier string, status scans.Status, finishedAt time.Time, exitCode *int, message string) error {
	result, err := s.database.ExecContext(ctx, `
		UPDATE scan_runs
		SET status = ?, finished_at = ?, exit_code = ?, error = ?
		WHERE id = ?
	`, status, formatTime(finishedAt), exitCode, message, identifier)
	return checkUpdated(result, err)
}

func (s *SQLite) SaveResult(ctx context.Context, identifier string, result scans.Result) error {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()

	updated, err := transaction.ExecContext(ctx, `
		UPDATE scan_runs
		SET nmap_version = ?, xml_output_version = ?, hosts_up = ?, hosts_down = ?, hosts_total = ?
		WHERE id = ?
	`, result.NmapVersion, result.XMLOutputVersion, result.HostsUp, result.HostsDown, result.HostsTotal, identifier)
	if err := checkUpdated(updated, err); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM scan_hosts WHERE scan_id = ?", identifier); err != nil {
		return err
	}
	for _, host := range result.Hosts {
		if _, err := insertHost(ctx, transaction, identifier, host); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (s *SQLite) SaveHost(ctx context.Context, scanID string, host scans.HostObservation) (scans.HostObservation, error) {
	if len(host.Addresses) == 0 {
		return scans.HostObservation{}, fmt.Errorf("host observation has no address")
	}
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return scans.HostObservation{}, err
	}
	defer transaction.Rollback()
	osMatches, err := json.Marshal(host.OSMatches)
	if err != nil {
		return scans.HostObservation{}, err
	}

	identity := host.Addresses[0]
	var hostID int64
	err = transaction.QueryRowContext(ctx, `
		SELECT h.id
		FROM scan_hosts h
		JOIN scan_host_addresses a ON a.host_id = h.id
		WHERE h.scan_id = ? AND a.address = ? AND a.address_type = ?
		ORDER BY h.id LIMIT 1
	`, scanID, identity.Address, identity.Type).Scan(&hostID)
	if errors.Is(err, sql.ErrNoRows) {
		hostID, err = insertHost(ctx, transaction, scanID, host)
	} else if err == nil {
		preservedNames, namesErr := hostnamesByType(ctx, transaction, hostID, "PTR")
		if namesErr != nil {
			return scans.HostObservation{}, namesErr
		}
		host.Hostnames = mergeHostnames(host.Hostnames, preservedNames)
		_, err = transaction.ExecContext(ctx, `
			UPDATE scan_hosts
			SET state = ?, state_reason = ?, provisional = ?, os_status = ?, os_matches_json = ?
			WHERE id = ?
		`, host.State, host.StateReason, host.Provisional, host.OSStatus, string(osMatches), hostID)
		if err == nil {
			for _, table := range []string{"scan_host_addresses", "scan_hostnames", "scan_ports"} {
				if _, err = transaction.ExecContext(ctx, "DELETE FROM "+table+" WHERE host_id = ?", hostID); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = insertHostChildren(ctx, transaction, hostID, host)
		}
	}
	if err != nil {
		return scans.HostObservation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return scans.HostObservation{}, err
	}
	if err := s.updateIncrementalCounts(ctx, scanID); err != nil {
		return scans.HostObservation{}, err
	}
	return s.GetHost(ctx, scanID, hostID)
}

func (s *SQLite) EnsureHost(ctx context.Context, scanID string, address scans.Address, hostnames []scans.Hostname, reason string) (scans.HostObservation, bool, error) {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return scans.HostObservation{}, false, err
	}
	defer transaction.Rollback()
	var hostID int64
	created := false
	err = transaction.QueryRowContext(ctx, `
		SELECT h.id FROM scan_hosts h
		JOIN scan_host_addresses a ON a.host_id = h.id
		WHERE h.scan_id = ? AND a.address = ? AND a.address_type = ?
		ORDER BY h.id LIMIT 1
	`, scanID, address.Address, address.Type).Scan(&hostID)
	if errors.Is(err, sql.ErrNoRows) {
		hostID, err = insertHost(ctx, transaction, scanID, scans.HostObservation{
			State: "up", StateReason: reason, Provisional: true,
			Addresses: []scans.Address{address}, Hostnames: hostnames,
		})
		created = err == nil
	} else if err == nil {
		for _, hostname := range hostnames {
			if _, err = transaction.ExecContext(ctx, `
				INSERT INTO scan_hostnames (host_id, name, hostname_type)
				SELECT ?, ?, ? WHERE NOT EXISTS (
					SELECT 1 FROM scan_hostnames WHERE host_id = ? AND lower(name) = lower(?)
				)
			`, hostID, hostname.Name, hostname.Type, hostID, hostname.Name); err != nil {
				break
			}
		}
	}
	if err != nil {
		return scans.HostObservation{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return scans.HostObservation{}, false, err
	}
	if created {
		if err := s.updateIncrementalCounts(ctx, scanID); err != nil {
			return scans.HostObservation{}, false, err
		}
	}
	host, err := s.GetHost(ctx, scanID, hostID)
	return host, created, err
}

func (s *SQLite) SaveHostEnrichment(ctx context.Context, scanID string, address scans.Address, hostnames []scans.Hostname, ownership *scans.Ownership) (scans.HostObservation, error) {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return scans.HostObservation{}, err
	}
	defer transaction.Rollback()
	var hostID int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT h.id FROM scan_hosts h
		JOIN scan_host_addresses a ON a.host_id = h.id
		WHERE h.scan_id = ? AND a.address = ? AND a.address_type = ?
		ORDER BY h.id LIMIT 1
	`, scanID, address.Address, address.Type).Scan(&hostID); errors.Is(err, sql.ErrNoRows) {
		return scans.HostObservation{}, scans.ErrNotFound
	} else if err != nil {
		return scans.HostObservation{}, err
	}
	for _, hostname := range hostnames {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO scan_hostnames (host_id, name, hostname_type)
			SELECT ?, ?, ? WHERE NOT EXISTS (
				SELECT 1 FROM scan_hostnames WHERE host_id = ? AND lower(name) = lower(?)
			)
		`, hostID, hostname.Name, hostname.Type, hostID, hostname.Name); err != nil {
			return scans.HostObservation{}, err
		}
	}
	if ownership != nil {
		encoded, err := json.Marshal(ownership)
		if err != nil {
			return scans.HostObservation{}, err
		}
		if _, err := transaction.ExecContext(ctx, "UPDATE scan_hosts SET ownership_json = ? WHERE id = ?", string(encoded), hostID); err != nil {
			return scans.HostObservation{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return scans.HostObservation{}, err
	}
	return s.GetHost(ctx, scanID, hostID)
}

func (s *SQLite) SaveScanOwnership(ctx context.Context, scanID string, ownership *scans.Ownership) (scans.Scan, error) {
	encoded, err := json.Marshal(ownership)
	if err != nil {
		return scans.Scan{}, err
	}
	updated, err := s.database.ExecContext(ctx, "UPDATE scan_runs SET ownership_json = ? WHERE id = ?", string(encoded), scanID)
	if err := checkUpdated(updated, err); err != nil {
		return scans.Scan{}, err
	}
	return s.Get(ctx, scanID)
}

func (s *SQLite) updateIncrementalCounts(ctx context.Context, scanID string) error {
	updated, err := s.database.ExecContext(ctx, `
		UPDATE scan_runs SET
			hosts_up = (SELECT COUNT(*) FROM scan_hosts WHERE scan_id = ? AND state = 'up'),
			hosts_down = (SELECT COUNT(*) FROM scan_hosts WHERE scan_id = ? AND state = 'down'),
			hosts_total = (SELECT COUNT(*) FROM scan_hosts WHERE scan_id = ?)
		WHERE id = ?
	`, scanID, scanID, scanID, scanID)
	return checkUpdated(updated, err)
}

func (s *SQLite) SaveSummary(ctx context.Context, identifier string, result scans.Result) error {
	updated, err := s.database.ExecContext(ctx, `
		UPDATE scan_runs
		SET nmap_version = ?, xml_output_version = ?, hosts_up = ?, hosts_down = ?, hosts_total = ?
		WHERE id = ?
	`, result.NmapVersion, result.XMLOutputVersion, result.HostsUp, result.HostsDown, result.HostsTotal, identifier)
	return checkUpdated(updated, err)
}

func (s *SQLite) ListTools(ctx context.Context, scanID string) ([]scans.ToolActivity, error) {
	var exists int
	if err := s.database.QueryRowContext(ctx, "SELECT 1 FROM scan_runs WHERE id = ?", scanID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return nil, scans.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	tools := make([]scans.ToolActivity, 0)
	rows, err := s.database.QueryContext(ctx, `
		SELECT provider_id, label, status
		FROM provider_runs WHERE scan_id = ? ORDER BY started_at, provider_id
	`, scanID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, label, runStatus string
		if err := rows.Scan(&id, &label, &runStatus); err != nil {
			rows.Close()
			return nil, err
		}
		if label == "" {
			label = id
		}
		tools = upsertTool(tools, scans.ToolActivity{ID: id, Label: label, Active: runStatus == "running"})
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tools, nil
}

func upsertTool(tools []scans.ToolActivity, tool scans.ToolActivity) []scans.ToolActivity {
	for index := range tools {
		if tools[index].ID == tool.ID {
			tools[index] = tool
			return tools
		}
	}
	return append(tools, tool)
}

func insertHost(ctx context.Context, transaction *sql.Tx, scanID string, host scans.HostObservation) (int64, error) {
	osMatches, err := json.Marshal(host.OSMatches)
	if err != nil {
		return 0, err
	}
	ownership, err := json.Marshal(host.Ownership)
	if err != nil {
		return 0, err
	}
	hostRow, err := transaction.ExecContext(ctx, `
		INSERT INTO scan_hosts (scan_id, state, state_reason, provisional, os_status, os_matches_json, ownership_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, scanID, host.State, host.StateReason, host.Provisional, host.OSStatus, string(osMatches), string(ownership))
	if err != nil {
		return 0, err
	}
	hostID, err := hostRow.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := insertHostChildren(ctx, transaction, hostID, host); err != nil {
		return 0, err
	}
	return hostID, nil
}

func hostnamesByType(ctx context.Context, transaction *sql.Tx, hostID int64, hostnameType string) ([]scans.Hostname, error) {
	rows, err := transaction.QueryContext(ctx, "SELECT name, hostname_type FROM scan_hostnames WHERE host_id = ? AND hostname_type = ? ORDER BY id", hostID, hostnameType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]scans.Hostname, 0)
	for rows.Next() {
		var hostname scans.Hostname
		if err := rows.Scan(&hostname.Name, &hostname.Type); err != nil {
			return nil, err
		}
		result = append(result, hostname)
	}
	return result, rows.Err()
}

func mergeHostnames(primary, preserved []scans.Hostname) []scans.Hostname {
	seen := make(map[string]struct{}, len(primary))
	for _, hostname := range primary {
		seen[strings.ToLower(hostname.Name)] = struct{}{}
	}
	for _, hostname := range preserved {
		if _, exists := seen[strings.ToLower(hostname.Name)]; exists {
			continue
		}
		primary = append(primary, hostname)
	}
	return primary
}

func insertHostChildren(ctx context.Context, transaction *sql.Tx, hostID int64, host scans.HostObservation) error {
	for _, address := range host.Addresses {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO scan_host_addresses (host_id, address, address_type, vendor)
			VALUES (?, ?, ?, ?)
		`, hostID, address.Address, address.Type, address.Vendor); err != nil {
			return err
		}
	}
	for _, hostname := range host.Hostnames {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO scan_hostnames (host_id, name, hostname_type) VALUES (?, ?, ?)
		`, hostID, hostname.Name, hostname.Type); err != nil {
			return err
		}
	}
	for _, port := range host.Ports {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO scan_ports (
				host_id, protocol, port_number, state, state_reason, service_name,
				product, version, extra_info, detection_method, confidence, tunnel
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, hostID, port.Protocol, port.Number, port.State, port.StateReason, port.Service,
			port.Product, port.Version, port.ExtraInfo, port.Method, port.Confidence, port.Tunnel); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLite) ListHosts(ctx context.Context, scanID string, limit, offset int) (scans.HostPage, error) {
	page := scans.HostPage{Items: make([]scans.HostSummary, 0), Limit: limit, Offset: offset}
	if err := s.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_hosts WHERE scan_id = ?", scanID).Scan(&page.Total); err != nil {
		return scans.HostPage{}, err
	}
	rows, err := s.database.QueryContext(ctx, `
		SELECT h.id, h.state,
		       COALESCE((SELECT a.address FROM scan_host_addresses a WHERE a.host_id = h.id
		                 ORDER BY CASE a.address_type WHEN 'ipv4' THEN 0 WHEN 'ipv6' THEN 1 ELSE 2 END, a.id LIMIT 1), ''),
		       COALESCE((SELECT a.address_type FROM scan_host_addresses a WHERE a.host_id = h.id
		                 ORDER BY CASE a.address_type WHEN 'ipv4' THEN 0 WHEN 'ipv6' THEN 1 ELSE 2 END, a.id LIMIT 1), ''),
		       COALESCE((SELECT a.vendor FROM scan_host_addresses a WHERE a.host_id = h.id AND a.vendor <> '' ORDER BY a.id LIMIT 1), ''),
		       COALESCE((SELECT n.name FROM scan_hostnames n WHERE n.host_id = h.id ORDER BY n.id LIMIT 1), ''),
		       (SELECT COUNT(*) FROM scan_ports p WHERE p.host_id = h.id AND p.state = 'open'),
		       EXISTS(SELECT 1 FROM scan_ports p WHERE p.host_id = h.id AND p.state = 'open'
		              AND p.protocol = 'tcp' AND p.port_number IN (80, 443)),
		       h.provisional
		FROM scan_hosts h
		WHERE h.scan_id = ?
		ORDER BY h.id
		LIMIT ? OFFSET ?
	`, scanID, limit, offset)
	if err != nil {
		return scans.HostPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var host scans.HostSummary
		if err := rows.Scan(&host.ID, &host.State, &host.Address, &host.AddressType, &host.Vendor, &host.Hostname, &host.OpenPortCount, &host.WebAvailable, &host.Provisional); err != nil {
			return scans.HostPage{}, err
		}
		page.Items = append(page.Items, host)
	}
	return page, rows.Err()
}

func (s *SQLite) GetHost(ctx context.Context, scanID string, hostID int64) (scans.HostObservation, error) {
	var host scans.HostObservation
	var osMatches, ownership string
	err := s.database.QueryRowContext(ctx, `
		SELECT id, state, state_reason, provisional, os_status, os_matches_json, ownership_json
		FROM scan_hosts WHERE scan_id = ? AND id = ?
	`, scanID, hostID).Scan(&host.ID, &host.State, &host.StateReason, &host.Provisional, &host.OSStatus, &osMatches, &ownership)
	if errors.Is(err, sql.ErrNoRows) {
		return scans.HostObservation{}, scans.ErrNotFound
	}
	if err != nil {
		return scans.HostObservation{}, err
	}
	host.Addresses = make([]scans.Address, 0)
	host.Hostnames = make([]scans.Hostname, 0)
	host.Ports = make([]scans.Port, 0)
	host.Evidence = make([]providers.Evidence, 0)
	if err := json.Unmarshal([]byte(osMatches), &host.OSMatches); err != nil {
		return scans.HostObservation{}, err
	}
	if err := json.Unmarshal([]byte(ownership), &host.Ownership); err != nil {
		return scans.HostObservation{}, err
	}
	addressRows, err := s.database.QueryContext(ctx, `
		SELECT address, address_type, vendor FROM scan_host_addresses WHERE host_id = ? ORDER BY id
	`, hostID)
	if err != nil {
		return scans.HostObservation{}, err
	}
	for addressRows.Next() {
		var address scans.Address
		if err := addressRows.Scan(&address.Address, &address.Type, &address.Vendor); err != nil {
			addressRows.Close()
			return scans.HostObservation{}, err
		}
		host.Addresses = append(host.Addresses, address)
	}
	if err := addressRows.Err(); err != nil {
		addressRows.Close()
		return scans.HostObservation{}, err
	}
	if err := addressRows.Close(); err != nil {
		return scans.HostObservation{}, err
	}
	hostnameRows, err := s.database.QueryContext(ctx, `
		SELECT name, hostname_type FROM scan_hostnames WHERE host_id = ? ORDER BY id
	`, hostID)
	if err != nil {
		return scans.HostObservation{}, err
	}
	for hostnameRows.Next() {
		var hostname scans.Hostname
		if err := hostnameRows.Scan(&hostname.Name, &hostname.Type); err != nil {
			hostnameRows.Close()
			return scans.HostObservation{}, err
		}
		host.Hostnames = append(host.Hostnames, hostname)
	}
	if err := hostnameRows.Err(); err != nil {
		hostnameRows.Close()
		return scans.HostObservation{}, err
	}
	if err := hostnameRows.Close(); err != nil {
		return scans.HostObservation{}, err
	}
	portRows, err := s.database.QueryContext(ctx, `
		SELECT protocol, port_number, state, state_reason, service_name, product, version,
		       extra_info, detection_method, confidence, tunnel
		FROM scan_ports WHERE host_id = ? ORDER BY port_number, protocol
	`, hostID)
	if err != nil {
		return scans.HostObservation{}, err
	}
	for portRows.Next() {
		var port scans.Port
		if err := portRows.Scan(&port.Protocol, &port.Number, &port.State, &port.StateReason, &port.Service,
			&port.Product, &port.Version, &port.ExtraInfo, &port.Method, &port.Confidence, &port.Tunnel); err != nil {
			return scans.HostObservation{}, err
		}
		host.Ports = append(host.Ports, port)
	}
	if err := portRows.Err(); err != nil {
		portRows.Close()
		return scans.HostObservation{}, err
	}
	if err := portRows.Close(); err != nil {
		return scans.HostObservation{}, err
	}
	for _, address := range host.Addresses {
		if address.Type != "ipv4" && address.Type != "ipv6" {
			continue
		}
		evidence, err := s.ListEvidence(ctx, scanID, providers.EvidenceQuery{SubjectType: "address", SubjectKey: address.Address, Limit: 500})
		if err != nil {
			return scans.HostObservation{}, err
		}
		host.Evidence = append(host.Evidence, evidence...)
	}
	return host, nil
}

func (s *SQLite) SaveRoute(ctx context.Context, scanID string, route scans.HostRoute) error {
	hops, err := json.Marshal(route.Hops)
	if err != nil {
		return err
	}
	_, err = s.database.ExecContext(ctx, `
		INSERT INTO scan_routes (scan_id, target, tool, hops_json, error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(scan_id, target) DO UPDATE SET
			tool = excluded.tool,
			hops_json = excluded.hops_json,
			error = excluded.error,
			updated_at = excluded.updated_at
	`, scanID, route.Target, route.Tool, string(hops), route.Error, formatTime(time.Now().UTC()))
	return err
}

func (s *SQLite) ListRoutes(ctx context.Context, scanID string) (scans.RouteMap, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT target, tool, hops_json, error
		FROM scan_routes WHERE scan_id = ? ORDER BY target
	`, scanID)
	if err != nil {
		return scans.RouteMap{}, err
	}
	defer rows.Close()
	result := scans.RouteMap{Routes: make([]scans.HostRoute, 0)}
	tools := make([]string, 0, 2)
	for rows.Next() {
		var route scans.HostRoute
		var hops string
		if err := rows.Scan(&route.Target, &route.Tool, &hops, &route.Error); err != nil {
			return scans.RouteMap{}, err
		}
		if err := json.Unmarshal([]byte(hops), &route.Hops); err != nil {
			return scans.RouteMap{}, err
		}
		result.Routes = append(result.Routes, route)
		if route.Tool != "" && !containsString(tools, route.Tool) {
			tools = append(tools, route.Tool)
		}
	}
	if err := rows.Err(); err != nil {
		return scans.RouteMap{}, err
	}
	result.Tool = strings.Join(tools, " / ")
	return result, nil
}

func (s *SQLite) CreateProviderRun(ctx context.Context, run providers.Run) error {
	_, err := s.database.ExecContext(ctx, `
		INSERT INTO provider_runs (id, scan_id, capability, provider_id, label, status, started_at, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, run.ID, run.ScanID, run.Capability, run.ProviderID, run.Label, run.Status, formatTime(run.StartedAt), run.Error)
	return err
}

func (s *SQLite) FinishProviderRun(ctx context.Context, identifier, status string, finishedAt time.Time, errorMessage string) error {
	updated, err := s.database.ExecContext(ctx, `
		UPDATE provider_runs SET status = ?, finished_at = ?, error = ? WHERE id = ?
	`, status, formatTime(finishedAt), errorMessage, identifier)
	return checkUpdated(updated, err)
}

func (s *SQLite) SaveEvidence(ctx context.Context, providerRunID string, evidence providers.Evidence) (providers.Evidence, error) {
	if evidence.Kind == "" || evidence.Subject.Type == "" || evidence.Subject.Key == "" {
		return providers.Evidence{}, errors.New("provider evidence requires kind and subject")
	}
	if evidence.PayloadVersion < 1 || !json.Valid(evidence.Payload) || len(evidence.Payload) > 1024*1024 {
		return providers.Evidence{}, errors.New("provider evidence payload is invalid or too large")
	}
	if evidence.ObservedAt.IsZero() {
		evidence.ObservedAt = time.Now().UTC()
	}
	var objectType, objectKey any
	if evidence.Object != nil {
		objectType = evidence.Object.Type
		objectKey = evidence.Object.Key
	}
	result, err := s.database.ExecContext(ctx, `
		INSERT INTO evidence (
			provider_run_id, kind, subject_type, subject_key, object_type, object_key,
			payload_version, payload_json, observed_at, confidence
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, providerRunID, evidence.Kind, evidence.Subject.Type, evidence.Subject.Key, objectType, objectKey,
		evidence.PayloadVersion, string(evidence.Payload), formatTime(evidence.ObservedAt), evidence.Confidence)
	if err != nil {
		return providers.Evidence{}, err
	}
	evidence.ID, err = result.LastInsertId()
	if err != nil {
		return providers.Evidence{}, err
	}
	evidence.ProviderRunID = providerRunID
	return evidence, nil
}

func (s *SQLite) ListEvidence(ctx context.Context, scanID string, query providers.EvidenceQuery) ([]providers.Evidence, error) {
	limit := query.Limit
	if limit < 1 || limit > 1000 {
		limit = 500
	}
	rows, err := s.database.QueryContext(ctx, `
		SELECT e.id, e.provider_run_id, pr.provider_id, pr.capability, e.kind,
		       e.subject_type, e.subject_key, e.object_type, e.object_key,
		       e.payload_version, e.payload_json, e.observed_at, e.confidence
		FROM evidence e
		JOIN provider_runs pr ON pr.id = e.provider_run_id
		WHERE pr.scan_id = ?
		  AND (? = '' OR e.kind = ?)
		  AND (? = '' OR e.subject_type = ?)
		  AND (? = '' OR e.subject_key = ?)
		ORDER BY e.observed_at, e.id
		LIMIT ?
	`, scanID, query.Kind, query.Kind, query.SubjectType, query.SubjectType,
		query.SubjectKey, query.SubjectKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]providers.Evidence, 0)
	for rows.Next() {
		var evidence providers.Evidence
		var objectType, objectKey sql.NullString
		var payload, observedAt string
		if err := rows.Scan(
			&evidence.ID, &evidence.ProviderRunID, &evidence.ProviderID, &evidence.Capability,
			&evidence.Kind, &evidence.Subject.Type, &evidence.Subject.Key, &objectType, &objectKey,
			&evidence.PayloadVersion, &payload, &observedAt, &evidence.Confidence,
		); err != nil {
			return nil, err
		}
		if objectType.Valid || objectKey.Valid {
			evidence.Object = &providers.EntityRef{Type: objectType.String, Key: objectKey.String}
		}
		evidence.Payload = json.RawMessage(payload)
		evidence.ObservedAt, err = parseTime(observedAt)
		if err != nil {
			return nil, err
		}
		result = append(result, evidence)
	}
	return result, rows.Err()
}

func (s *SQLite) InterruptRunning(ctx context.Context, finishedAt time.Time) error {
	_, err := s.database.ExecContext(ctx, `
		UPDATE scan_runs
		SET status = ?, finished_at = ?, error = ?
		WHERE status IN (?, ?)
	`, scans.StatusInterrupted, formatTime(finishedAt), "Lantern stopped before the scan completed", scans.StatusQueued, scans.StatusRunning)
	return err
}

func (s *SQLite) migrate(ctx context.Context) error {
	if _, err := s.database.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	var version int
	if err := s.database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version < 1 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := transaction.ExecContext(ctx, `
		CREATE TABLE scan_runs (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			arguments_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			started_at TEXT,
			finished_at TEXT,
			exit_code INTEGER,
			output TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT ''
		)
		`); err != nil {
			return fmt.Errorf("create scan_runs: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
		INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 1
	}
	if version < 2 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		for _, statement := range []string{
			"ALTER TABLE scan_runs ADD COLUMN nmap_version TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scan_runs ADD COLUMN xml_output_version TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scan_runs ADD COLUMN hosts_up INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scan_runs ADD COLUMN hosts_down INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scan_runs ADD COLUMN hosts_total INTEGER NOT NULL DEFAULT 0",
			`CREATE TABLE scan_hosts (
				id INTEGER PRIMARY KEY,
				scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
				state TEXT NOT NULL,
				state_reason TEXT NOT NULL DEFAULT ''
			)`,
			"CREATE INDEX scan_hosts_scan_id ON scan_hosts(scan_id)",
			`CREATE TABLE scan_host_addresses (
				id INTEGER PRIMARY KEY,
				host_id INTEGER NOT NULL REFERENCES scan_hosts(id) ON DELETE CASCADE,
				address TEXT NOT NULL,
				address_type TEXT NOT NULL,
				vendor TEXT NOT NULL DEFAULT ''
			)`,
			"CREATE INDEX scan_host_addresses_host_id ON scan_host_addresses(host_id)",
			`CREATE TABLE scan_hostnames (
				id INTEGER PRIMARY KEY,
				host_id INTEGER NOT NULL REFERENCES scan_hosts(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				hostname_type TEXT NOT NULL DEFAULT ''
			)`,
			"CREATE INDEX scan_hostnames_host_id ON scan_hostnames(host_id)",
			`CREATE TABLE scan_ports (
				id INTEGER PRIMARY KEY,
				host_id INTEGER NOT NULL REFERENCES scan_hosts(id) ON DELETE CASCADE,
				protocol TEXT NOT NULL,
				port_number INTEGER NOT NULL CHECK (port_number BETWEEN 1 AND 65535),
				state TEXT NOT NULL,
				state_reason TEXT NOT NULL DEFAULT '',
				service_name TEXT NOT NULL DEFAULT '',
				product TEXT NOT NULL DEFAULT '',
				version TEXT NOT NULL DEFAULT '',
				extra_info TEXT NOT NULL DEFAULT '',
				detection_method TEXT NOT NULL DEFAULT '',
				confidence INTEGER NOT NULL DEFAULT 0,
				tunnel TEXT NOT NULL DEFAULT '',
				UNIQUE(host_id, protocol, port_number)
			)`,
			"CREATE INDEX scan_ports_host_id ON scan_ports(host_id)",
		} {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration 2: %w", err)
			}
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 2
	}
	if version < 3 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := transaction.ExecContext(ctx, `
			ALTER TABLE scan_hosts ADD COLUMN provisional INTEGER NOT NULL DEFAULT 0
		`); err != nil {
			return fmt.Errorf("apply migration 3: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (3, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 3
	}
	if version < 4 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		for _, statement := range []string{
			"ALTER TABLE scan_runs ADD COLUMN profile_id TEXT NOT NULL DEFAULT 'builtin:quick'",
			`CREATE TABLE scan_profiles (
				id TEXT PRIMARY KEY,
				argument_text TEXT NOT NULL,
				arguments_json TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
		} {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration 4: %w", err)
			}
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (4, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 4
	}
	if version < 5 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		for _, statement := range []string{
			"ALTER TABLE scan_runs ADD COLUMN os_detection INTEGER NOT NULL DEFAULT 0",
			"ALTER TABLE scan_hosts ADD COLUMN os_status TEXT NOT NULL DEFAULT ''",
			"ALTER TABLE scan_hosts ADD COLUMN os_matches_json TEXT NOT NULL DEFAULT '[]'",
		} {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration 5: %w", err)
			}
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (5, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 5
	}
	if version < 6 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := transaction.ExecContext(ctx, `
			CREATE TABLE scan_routes (
				scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
				target TEXT NOT NULL,
				tool TEXT NOT NULL DEFAULT '',
				hops_json TEXT NOT NULL DEFAULT '[]',
				error TEXT NOT NULL DEFAULT '',
				updated_at TEXT NOT NULL,
				PRIMARY KEY (scan_id, target)
			)
		`); err != nil {
			return fmt.Errorf("apply migration 6: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (6, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 6
	}
	if version < 7 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := transaction.ExecContext(ctx, `
			ALTER TABLE scan_hosts ADD COLUMN ownership_json TEXT NOT NULL DEFAULT 'null'
		`); err != nil {
			return fmt.Errorf("apply migration 7: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (7, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 7
	}
	if version < 8 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := transaction.ExecContext(ctx, `
			ALTER TABLE scan_runs ADD COLUMN ownership_json TEXT NOT NULL DEFAULT 'null'
		`); err != nil {
			return fmt.Errorf("apply migration 8: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (8, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 8
	}
	if version < 9 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		for _, statement := range []string{
			`CREATE TABLE provider_runs (
				id TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
				capability TEXT NOT NULL,
				provider_id TEXT NOT NULL,
				status TEXT NOT NULL,
				started_at TEXT NOT NULL,
				finished_at TEXT,
				error TEXT NOT NULL DEFAULT ''
			)`,
			"CREATE INDEX provider_runs_scan_id ON provider_runs(scan_id)",
			`CREATE TABLE evidence (
				id INTEGER PRIMARY KEY,
				provider_run_id TEXT NOT NULL REFERENCES provider_runs(id) ON DELETE CASCADE,
				kind TEXT NOT NULL,
				subject_type TEXT NOT NULL,
				subject_key TEXT NOT NULL,
				object_type TEXT,
				object_key TEXT,
				payload_version INTEGER NOT NULL CHECK (payload_version > 0),
				payload_json TEXT NOT NULL CHECK (length(payload_json) <= 1048576),
				observed_at TEXT NOT NULL,
				confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1)
			)`,
			"CREATE INDEX evidence_provider_run_id ON evidence(provider_run_id)",
			"CREATE INDEX evidence_subject ON evidence(subject_type, subject_key)",
			"CREATE INDEX evidence_kind ON evidence(kind)",
		} {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration 9: %w", err)
			}
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (9, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
		version = 9
	}
	if version < 10 {
		transaction, err := s.database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer transaction.Rollback()
		if _, err := transaction.ExecContext(ctx, `
			ALTER TABLE provider_runs ADD COLUMN label TEXT NOT NULL DEFAULT ''
		`); err != nil {
			return fmt.Errorf("apply migration 10: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, applied_at) VALUES (10, ?)
		`, formatTime(time.Now().UTC())); err != nil {
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

const selectScan = `
	SELECT id, target, profile_id, os_detection, status, arguments_json, created_at, started_at, finished_at,
	       exit_code, output, error, nmap_version, xml_output_version,
	       hosts_up, hosts_down, hosts_total, ownership_json
	FROM scan_runs
`

const selectAllScans = `
	SELECT id, target, profile_id, os_detection, status, arguments_json, created_at, started_at, finished_at,
	       exit_code, output, error, nmap_version, xml_output_version,
	       hosts_up, hosts_down, hosts_total, ownership_json
	FROM scan_runs
	ORDER BY created_at DESC
`

type rowScanner interface {
	Scan(...any) error
}

func readScan(row rowScanner) (scans.Scan, error) {
	var scan scans.Scan
	var status string
	var arguments string
	var createdAt string
	var startedAt sql.NullString
	var finishedAt sql.NullString
	var exitCode sql.NullInt64
	var ownership string
	if err := row.Scan(
		&scan.ID,
		&scan.Target,
		&scan.ProfileID,
		&scan.OSDetection,
		&status,
		&arguments,
		&createdAt,
		&startedAt,
		&finishedAt,
		&exitCode,
		&scan.Output,
		&scan.Error,
		&scan.NmapVersion,
		&scan.XMLOutputVersion,
		&scan.HostsUp,
		&scan.HostsDown,
		&scan.HostsTotal,
		&ownership,
	); err != nil {
		return scans.Scan{}, err
	}
	scan.Status = scans.Status(status)
	if err := json.Unmarshal([]byte(arguments), &scan.Arguments); err != nil {
		return scans.Scan{}, err
	}
	if err := json.Unmarshal([]byte(ownership), &scan.Ownership); err != nil {
		return scans.Scan{}, err
	}
	var err error
	scan.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return scans.Scan{}, err
	}
	if startedAt.Valid {
		value, err := parseTime(startedAt.String)
		if err != nil {
			return scans.Scan{}, err
		}
		scan.StartedAt = &value
	}
	if finishedAt.Valid {
		value, err := parseTime(finishedAt.String)
		if err != nil {
			return scans.Scan{}, err
		}
		scan.FinishedAt = &value
	}
	if exitCode.Valid {
		value := int(exitCode.Int64)
		scan.ExitCode = &value
	}
	return scan, nil
}

func readProfile(row rowScanner) (scans.Profile, error) {
	var profile scans.Profile
	var arguments, createdAt, updatedAt string
	if err := row.Scan(&profile.ID, &profile.ArgumentText, &arguments, &createdAt, &updatedAt); err != nil {
		return scans.Profile{}, err
	}
	if err := json.Unmarshal([]byte(arguments), &profile.Arguments); err != nil {
		return scans.Profile{}, err
	}
	var err error
	created, err := parseTime(createdAt)
	if err != nil {
		return scans.Profile{}, err
	}
	profile.CreatedAt = &created
	updated, err := parseTime(updatedAt)
	if err != nil {
		return scans.Profile{}, err
	}
	profile.UpdatedAt = &updated
	return profile, nil
}

func checkUpdated(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return scans.ErrNotFound
	}
	return nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(timestampFormat)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(timestampFormat, value)
}
