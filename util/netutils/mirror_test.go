package netutils

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func withMirror(dir string, off bool, cache CacheOptions) func() {
	prevDir, prevOff, prevCache := mirrorDir, offline, cacheOpts
	SetMirror(dir, off)
	SetCacheOptions(cache)
	return func() {
		mirrorDir, offline = prevDir, prevOff
		SetCacheOptions(prevCache)
	}
}

func TestMirrorFileUsedWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ir.txt"), []byte("192.0.2.1\n192.0.2.2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// The default source URLs are unreachable in tests; the mirror must answer first.
	defer withMirror(dir, false, CacheOptions{Dir: ""})()
	got, err := FetchIPPool("IR", false, "", "")
	if err != nil {
		t.Fatalf("FetchIPPool: %v", err)
	}
	if want := []string{"192.0.2.1/32", "192.0.2.2/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOfflineWithoutMirrorOrCacheFails(t *testing.T) {
	defer withMirror(t.TempDir(), true, CacheOptions{Dir: t.TempDir(), MaxAge: time.Hour})()
	if _, err := FetchIPPool("ir", false, "", ""); err == nil {
		t.Fatal("expected error in offline mode with no mirror file and no cache")
	}
}

func TestOfflineUsesCacheWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	defer withMirror("", false, CacheOptions{Dir: dir, MaxAge: time.Hour})()
	var hits int32
	srv := serve(t, 200, "192.0.2.9\n", &hits)
	// Seed the cache for a known URL, then go offline.
	if err := storeLines(srv.URL, []string{"192.0.2.9"}); err != nil {
		t.Fatal(err)
	}
	SetMirror("", true)
	before := hits
	got, err := fetchFromSources([]string{srv.URL}, false, "")
	if err != nil {
		t.Fatalf("offline with cache: %v", err)
	}
	if want := []string{"192.0.2.9/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if hits != before {
		t.Errorf("network contacted in offline mode")
	}
}
