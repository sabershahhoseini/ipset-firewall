package ipsetfw

import (
	"time"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
	"github.com/sabershahhoseini/ipset-firewall/util/netutils"
)

// ForceRefresh is set by -force: fresh cached lists are ignored and downloaded again.
var ForceRefresh bool

// MirrorFlag and OfflineFlag are set by -mirror and -offline. A config value takes precedence.
var (
	MirrorFlag  string
	OfflineFlag bool
)

// configureSources applies the cache and mirror settings of a config. off disables the
// cache and keeps the mirror read-only (used by -plan).
func configureSources(inv file.Inventory, off bool) error {
	if err := configureCache(inv.Cache, off); err != nil {
		return err
	}
	mirror := MirrorFlag
	if inv.Mirror != "" {
		mirror = inv.Mirror
	}
	netutils.SetMirror(mirror, inv.Offline || OfflineFlag)
	return nil
}

// configureCache applies the cache section of a config. off disables reads and writes
// (used by -plan, which must not change anything).
func configureCache(c file.CacheConfig, off bool) error {
	o := netutils.CacheOptions{
		Dir:    netutils.DefaultCacheDir,
		MaxAge: netutils.DefaultCacheMaxAge,
		Force:  ForceRefresh,
	}
	if c.Dir != "" {
		o.Dir = c.Dir
	}
	if c.Dir == "off" {
		o.Dir = ""
	}
	if c.MaxAge != "" {
		d, err := time.ParseDuration(c.MaxAge)
		if err != nil {
			return err
		}
		o.MaxAge = d
	}
	if off {
		o.Dir = ""
	}
	netutils.SetCacheOptions(o)
	return nil
}
