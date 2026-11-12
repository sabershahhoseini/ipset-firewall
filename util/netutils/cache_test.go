package netutils

import (
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"
)

// TestMain points the cache at a temporary directory so tests never touch /var/cache.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ipsetfw-cache-test")
	if err != nil {
		panic(err)
	}
	SetCacheOptions(CacheOptions{Dir: dir, MaxAge: DefaultCacheMaxAge})
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// withCache sets cache options for one test and returns a function that restores them.
func withCache(o CacheOptions) func() {
	prev := cacheOpts
	SetCacheOptions(o)
	return func() { SetCacheOptions(prev) }
}

func TestFreshCacheSkipsNetwork(t *testing.T) {
	defer withCache(CacheOptions{Dir: t.TempDir(), MaxAge: time.Hour})()
	var hits int32
	srv := serve(t, http.StatusOK, "192.0.2.1\n", &hits)
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits after first fetch = %d, want 1", hits)
	}
	got, err := fetchFromSources([]string{srv.URL}, false, "")
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if want := []string{"192.0.2.1/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if hits != 1 {
		t.Errorf("source contacted again inside MaxAge: hits = %d", hits)
	}
}

func TestForceBypassesFreshCache(t *testing.T) {
	dir := t.TempDir()
	defer withCache(CacheOptions{Dir: dir, MaxAge: time.Hour})()
	var hits int32
	srv := serve(t, http.StatusOK, "192.0.2.1\n", &hits)
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	SetCacheOptions(CacheOptions{Dir: dir, MaxAge: time.Hour, Force: true})
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2 with Force", hits)
	}
}

func TestExpiredCacheIsRefreshed(t *testing.T) {
	defer withCache(CacheOptions{Dir: t.TempDir(), MaxAge: time.Hour})()
	var hits int32
	srv := serve(t, http.StatusOK, "192.0.2.1\n", &hits)
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	SetCacheOptions(CacheOptions{Dir: cacheOpts.Dir, MaxAge: time.Nanosecond})
	time.Sleep(time.Millisecond)
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2 after expiry", hits)
	}
}

func TestLastGoodFallbackWhenAllSourcesFail(t *testing.T) {
	defer withCache(CacheOptions{Dir: t.TempDir(), MaxAge: time.Hour})()
	var hits int32
	srv := serve(t, http.StatusOK, "192.0.2.1\n198.51.100.1\n", &hits)
	url := srv.URL
	if _, err := fetchFromSources([]string{url}, false, ""); err != nil {
		t.Fatal(err)
	}
	// Make the copy stale, then take the source down.
	SetCacheOptions(CacheOptions{Dir: cacheOpts.Dir, MaxAge: time.Nanosecond})
	time.Sleep(time.Millisecond)
	srv.Close()
	got, err := fetchFromSources([]string{url}, false, "")
	if err != nil {
		t.Fatalf("fallback should return the cached copy, got error: %v", err)
	}
	if want := []string{"192.0.2.1/32", "198.51.100.1/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCacheDisabledMeansNoFallback(t *testing.T) {
	defer withCache(CacheOptions{Dir: "", MaxAge: time.Hour})()
	srv := serve(t, http.StatusInternalServerError, "", nil)
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err == nil {
		t.Fatal("expected error with cache disabled and source down")
	}
}

func TestReadOnlyCacheReadsButNeverWrites(t *testing.T) {
	dir := t.TempDir()
	defer withCache(CacheOptions{Dir: dir, MaxAge: time.Hour})()
	var hits int32
	srv := serve(t, http.StatusOK, "192.0.2.1\n", &hits)
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	// Read-only: the fresh copy is used without contacting the source.
	SetCacheOptions(CacheOptions{Dir: dir, MaxAge: time.Hour, ReadOnly: true})
	if _, err := fetchFromSources([]string{srv.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("read-only mode downloaded although a fresh copy exists: hits=%d", hits)
	}
	// Read-only: a new download is not stored.
	other := serve(t, http.StatusOK, "198.51.100.1\n", nil)
	if _, err := fetchFromSources([]string{other.URL}, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := cachedLines(other.URL); ok {
		t.Error("read-only mode wrote a cache entry")
	}
}
