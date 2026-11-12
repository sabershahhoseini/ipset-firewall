package netutils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultCacheDir holds the last successful copy of every downloaded list.
const DefaultCacheDir = "/var/cache/ipsetfw"

// DefaultCacheMaxAge is how long a cached list counts as fresh.
const DefaultCacheMaxAge = 12 * time.Hour

// CacheOptions controls the list cache. An empty Dir disables caching entirely.
type CacheOptions struct {
	Dir    string
	MaxAge time.Duration
	// Force ignores fresh cache entries and downloads again. New copies are still stored.
	Force bool
}

var cacheOpts = CacheOptions{Dir: DefaultCacheDir, MaxAge: DefaultCacheMaxAge}

// SetCacheOptions replaces the cache settings used by FetchIPPool.
func SetCacheOptions(o CacheOptions) {
	cacheOpts = o
}

func cachePath(dir, url string) string {
	h := sha256.Sum256([]byte(url))
	return filepath.Join(dir, hex.EncodeToString(h[:])+".txt")
}

// cachedLines returns the cached copy of url and its age, if one exists.
func cachedLines(url string) ([]string, time.Duration, bool) {
	if cacheOpts.Dir == "" {
		return nil, 0, false
	}
	p := cachePath(cacheOpts.Dir, url)
	st, err := os.Stat(p)
	if err != nil {
		return nil, 0, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, 0, false
	}
	return strings.Split(string(b), "\n"), time.Since(st.ModTime()), true
}

// storeLines writes the downloaded lines for url, replacing any older copy atomically.
func storeLines(url string, lines []string) error {
	if cacheOpts.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(cacheOpts.Dir, 0755); err != nil {
		return err
	}
	final := cachePath(cacheOpts.Dir, url)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// humanAge formats an age for messages, for example "3h10m".
func humanAge(d time.Duration) string {
	return fmt.Sprint(d.Round(time.Minute))
}
