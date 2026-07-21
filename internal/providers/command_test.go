package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveExecutable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	executableFile := filepath.Join(directory, "standard-tool")
	nonExecutable := filepath.Join(directory, "plain-file")
	if err := os.WriteFile(executableFile, []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nonExecutable, []byte("tool"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		configured string
		fallback   string
		standards  []string
		want       string
	}{
		{name: "configured absolute", configured: "  " + executable + "  ", want: executable},
		{name: "configured missing", configured: "lantern-command-missing"},
		{name: "PATH fallback", fallback: filepath.Base(executableFile), want: executableFile},
		{name: "standard path", fallback: "lantern-command-missing", standards: []string{nonExecutable, directory, executableFile}, want: executableFile},
		{name: "no executable", fallback: "lantern-command-missing", standards: []string{nonExecutable, directory}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PATH", directory)
			if got := ResolveExecutable(test.configured, test.fallback, test.standards); got != test.want {
				t.Fatalf("ResolveExecutable() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCommandContextConfiguresProcessGroup(t *testing.T) {
	command := CommandContext(context.Background(), os.Args[0], "-test.run=^$")
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid {
		t.Fatalf("process attributes = %#v", command.SysProcAttr)
	}
	if err := command.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("Cancel before start = %v", err)
	}
}

func TestExecRunner(t *testing.T) {
	t.Run("captures output", func(t *testing.T) {
		result, err := runCommandHelper(t, context.Background(), "output", 10*time.Second, 1024)
		if err != nil || string(result.Stdout) != "stdout" || string(result.Stderr) != "stderr" {
			t.Fatalf("result = %#v, %v", result, err)
		}
	})

	t.Run("nonzero exit", func(t *testing.T) {
		result, err := runCommandHelper(t, context.Background(), "fail", 10*time.Second, 1024)
		if err == nil || !strings.Contains(err.Error(), "exit status") || string(result.Stderr) != "failed" {
			t.Fatalf("result = %#v, %v", result, err)
		}
	})

	t.Run("output limit", func(t *testing.T) {
		result, err := runCommandHelper(t, context.Background(), "large", 10*time.Second, 4)
		if !errors.Is(err, ErrOutputLimit) || string(result.Stdout) != "1234" || string(result.Stderr) != "abcd" {
			t.Fatalf("result = %#v, %v", result, err)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		_, err := runCommandHelper(t, context.Background(), "sleep", 20*time.Millisecond, 1024)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("parent cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := runCommandHelper(t, ctx, "sleep", time.Second, 1024)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCappedBuffer(t *testing.T) {
	for _, limit := range []int{-1, 0} {
		buffer := newCappedBuffer(limit)
		if n, err := buffer.Write([]byte("discarded")); err != nil || n != len("discarded") || !buffer.truncated || len(buffer.Bytes()) != 0 {
			t.Fatalf("limit %d: n=%d buffer=%#v bytes=%q err=%v", limit, n, buffer, buffer.Bytes(), err)
		}
	}

	buffer := newCappedBuffer(4)
	if n, err := buffer.Write([]byte("1234")); err != nil || n != 4 || buffer.truncated {
		t.Fatalf("exact write: n=%d buffer=%#v err=%v", n, buffer, err)
	}
	if n, err := buffer.Write([]byte("56")); err != nil || n != 2 || !buffer.truncated || string(buffer.Bytes()) != "1234" {
		t.Fatalf("overflow write: n=%d buffer=%#v err=%v", n, buffer, err)
	}
	copyOfBytes := buffer.Bytes()
	copyOfBytes[0] = 'x'
	if string(buffer.Bytes()) != "1234" {
		t.Fatal("Bytes exposed internal storage")
	}
}

func runCommandHelper(t *testing.T, ctx context.Context, mode string, timeout time.Duration, limit int) (CommandResult, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_COMMAND_HELPER", "1")
	return (ExecRunner{}).Run(ctx, executable, []string{"-test.run=TestCommandHelperProcess", "--", mode}, timeout, limit)
}

func TestCommandHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_COMMAND_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "output":
		_, _ = fmt.Fprint(os.Stdout, "stdout")
		_, _ = fmt.Fprint(os.Stderr, "stderr")
	case "fail":
		_, _ = fmt.Fprint(os.Stderr, "failed")
		os.Exit(2)
	case "large":
		_, _ = fmt.Fprint(os.Stdout, "12345678")
		_, _ = fmt.Fprint(os.Stderr, "abcdefgh")
	case "sleep":
		time.Sleep(time.Second)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}
