// Package lock provides a non-blocking exclusive lock so two runs cannot change the firewall at once.
package lock

import (
	"fmt"
	"os"
	"syscall"
)

// Acquire takes an exclusive lock on path without waiting. The lock is released when the
// returned file is closed. If another process holds it, Acquire returns an error at once.
func Acquire(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another ipsetfw run holds %s", path)
	}
	return f, nil
}
