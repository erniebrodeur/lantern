//go:build darwin || linux

package scans

import (
	"os"
)

func runningPrivileged() bool {
	return os.Geteuid() == 0
}
