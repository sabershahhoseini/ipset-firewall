package lock

import (
	"path/filepath"
	"testing"
)

func TestSecondAcquireFailsWhileHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsetfw.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if second, err := Acquire(path); err == nil {
		second.Close()
		t.Fatal("second acquire succeeded while the first is held")
	}
	first.Close()
	again, err := Acquire(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	again.Close()
}
