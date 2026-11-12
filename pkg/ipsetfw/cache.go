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

// configureSources applies the cache and mirror settings of a config. readOnly is used by -plan.
func configureSources(inv file.Inventory, readOnly bool) error {
	if err := configureCache(inv.Cache, readOnly); err != nil {
		return err
	}
	mirror := MirrorFlag
	if inv.Mirror != "" {
		mirror = inv.Mirror
	}
	netutils.SetMirror(mirror, inv.Offline || OfflineFlag)
	return nil
}

// configureCache applies the cache section of a config. readOnly keeps using cached copies but
// never writes new ones (used by -plan, which must not change anything).
func configureCache(c file.CacheConfig, readOnly bool) error {
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
	o.ReadOnly = readOnly
	netutils.SetCacheOptions(o)
	return nil
}
