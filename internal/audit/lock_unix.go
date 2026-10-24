//go:build unix

package audit

import (
	"fmt"
	"os"
	"syscall"
)

// lock takes a non-blocking exclusive lock held until the file is closed.
func lock(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("log is locked by another process: %w", err)
	}
	return nil
}
