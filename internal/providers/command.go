package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrOutputLimit indicates that a command produced more output than allowed.
var ErrOutputLimit = errors.New("provider output exceeded its limit")

// CommandResult contains the captured output streams of an external command.
type CommandResult struct {
	Stdout []byte
	Stderr []byte
}

// CommandRunner executes provider commands with time and output limits.
type CommandRunner interface {
	Run(context.Context, string, []string, time.Duration, int) (CommandResult, error)
}

// ExecRunner executes commands as child processes without invoking a shell.
type ExecRunner struct{}

// ResolveExecutable finds a configured command, a PATH fallback, or a standard
// executable path, in that order.
func ResolveExecutable(configured, fallback string, standardPaths []string) string {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		if path, err := exec.LookPath(configured); err == nil {
			return path
		}
		return ""
	}
	if path, err := exec.LookPath(fallback); err == nil {
		return path
	}
	for _, path := range standardPaths {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return path
		}
	}
	return ""
}

// CommandContext creates a platform-configured command without invoking a shell.
func CommandContext(ctx context.Context, path string, arguments ...string) *exec.Cmd {
	// Paths come from provider probes and arguments cross typed validation
	// boundaries. Providers never invoke a shell.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	command := exec.CommandContext(ctx, path, arguments...)
	configureProcess(command)
	return command
}

// Run executes path with a deadline and independently capped output streams.
func (ExecRunner) Run(parent context.Context, path string, arguments []string, timeout time.Duration, maxOutputBytes int) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	stdout := newCappedBuffer(maxOutputBytes)
	stderr := newCappedBuffer(maxOutputBytes)
	command := CommandContext(ctx, path, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if stdout.truncated || stderr.truncated {
		return result, ErrOutputLimit
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil {
		return result, fmt.Errorf("run %s: %w", path, err)
	}
	return result, nil
}

type cappedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func newCappedBuffer(limit int) *cappedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &cappedBuffer{remaining: limit}
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	if len(data) > b.remaining {
		data = data[:b.remaining]
		b.truncated = true
	}
	if len(data) > 0 {
		_, _ = b.buffer.Write(data)
		b.remaining -= len(data)
	}
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte {
	return append([]byte(nil), b.buffer.Bytes()...)
}
