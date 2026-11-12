package file

import (
	"fmt"
	"net/url"
	"path/filepath"
	"time"
)

// WebhookLabel is how a webhook is shown in messages: scheme and host only. The path and query
// of a webhook URL often hold a secret token, so they are never printed.
func WebhookLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "webhook"
	}
	return "webhook " + u.Scheme + "://" + u.Hostname()
}

// DefaultHookTimeout is how long a hook may run when no timeout is set.
const DefaultHookTimeout = 30 * time.Second

// Hook is one thing to do at a point in a run: run a program, or (later) call a webhook.
type Hook struct {
	// Run is a program and its arguments. Run[0] must be an absolute path. No shell is used.
	Run []string `yaml:"run"`
	// Webhook is a URL that receives the run report as JSON.
	Webhook string `yaml:"webhook"`
	// When is "always" (default) or "changed" (after hooks only).
	When string `yaml:"when"`
	// OnFailure: before hooks abort|warn (default abort); after hooks warn|rollback (default
	// warn); onError hooks warn.
	OnFailure string `yaml:"onFailure"`
	// Timeout overrides the default for this hook, a Go duration such as "10s".
	Timeout string `yaml:"timeout"`
	// Retries is how often a webhook is retried after a failure (0-10).
	Retries int `yaml:"retries"`
}

// HooksConfig lists the hooks of each event, run in order.
type HooksConfig struct {
	Timeout string `yaml:"timeout"`
	Before  []Hook `yaml:"before"`
	After   []Hook `yaml:"after"`
	OnError []Hook `yaml:"onError"`
}

// Any reports whether any hook is configured.
func (h HooksConfig) Any() bool {
	return len(h.Before)+len(h.After)+len(h.OnError) > 0
}

// TimeoutFor returns the timeout of a hook: its own, else the section default, else 30s.
// Validate has already checked that these parse.
func (h HooksConfig) TimeoutFor(hook Hook) time.Duration {
	for _, s := range []string{hook.Timeout, h.Timeout} {
		if s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
		}
	}
	return DefaultHookTimeout
}

// OnFailureOrDefault returns the failure policy of a hook for an event: the default is abort
// for before hooks and warn for the others.
func (hk Hook) OnFailureOrDefault(event string) string {
	if hk.OnFailure != "" {
		return hk.OnFailure
	}
	if event == "before" {
		return "abort"
	}
	return "warn"
}

// Name is a short label for messages: the program, or the webhook's scheme and host (never its URL).
func (hk Hook) Name() string {
	if len(hk.Run) > 0 {
		return hk.Run[0]
	}
	return WebhookLabel(hk.Webhook)
}

// validate checks the hooks of one event.
func (h HooksConfig) validateEvent(event string, hooks []Hook) error {
	for i, hk := range hooks {
		where := fmt.Sprintf("hooks.%s[%d]", event, i+1)
		hasRun, hasWebhook := len(hk.Run) > 0, hk.Webhook != ""
		switch {
		case hasRun && hasWebhook:
			return fmt.Errorf("%s: set either run or webhook, not both", where)
		case !hasRun && !hasWebhook:
			return fmt.Errorf("%s: set run (a program) or webhook", where)
		case hasWebhook:
			// The URL itself is never put in an error: it may contain a token.
			u, err := url.Parse(hk.Webhook)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return fmt.Errorf("%s: webhook must be an http:// or https:// URL", where)
			}
		default:
			if !filepath.IsAbs(hk.Run[0]) {
				return fmt.Errorf("%s: run[0] must be an absolute path, got %q", where, hk.Run[0])
			}
		}
		switch event {
		case "before":
			if hk.When != "" {
				return fmt.Errorf("%s: when is only for after hooks", where)
			}
			if hk.OnFailure != "" && hk.OnFailure != "abort" && hk.OnFailure != "warn" {
				return fmt.Errorf("%s: onFailure must be abort or warn, got %q", where, hk.OnFailure)
			}
		case "after":
			if hk.When != "" && hk.When != "always" && hk.When != "changed" {
				return fmt.Errorf("%s: when must be always or changed, got %q", where, hk.When)
			}
			if hk.OnFailure != "" && hk.OnFailure != "warn" && hk.OnFailure != "rollback" {
				return fmt.Errorf("%s: onFailure must be warn or rollback, got %q", where, hk.OnFailure)
			}
		case "onError":
			if hk.When != "" {
				return fmt.Errorf("%s: when is only for after hooks", where)
			}
			if hk.OnFailure != "" && hk.OnFailure != "warn" {
				return fmt.Errorf("%s: onFailure must be warn, got %q", where, hk.OnFailure)
			}
		}
		if hk.Timeout != "" {
			if d, err := time.ParseDuration(hk.Timeout); err != nil || d <= 0 {
				return fmt.Errorf("%s: timeout must be a positive duration such as 10s, got %q", where, hk.Timeout)
			}
		}
		if hk.Retries < 0 || hk.Retries > 10 {
			return fmt.Errorf("%s: retries must be 0 to 10, got %d", where, hk.Retries)
		}
	}
	return nil
}

// Validate checks the whole hooks section.
func (h HooksConfig) Validate() error {
	if h.Timeout != "" {
		if d, err := time.ParseDuration(h.Timeout); err != nil || d <= 0 {
			return fmt.Errorf("hooks.timeout must be a positive duration such as 30s, got %q", h.Timeout)
		}
	}
	if err := h.validateEvent("before", h.Before); err != nil {
		return err
	}
	if err := h.validateEvent("after", h.After); err != nil {
		return err
	}
	return h.validateEvent("onError", h.OnError)
}
