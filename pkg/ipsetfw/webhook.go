package ipsetfw

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
)

// webhookBackoff is the wait before the first retry; it doubles each time, up to 30 seconds.
// Tests make it small.
var webhookBackoff = time.Second

const webhookBackoffCap = 30 * time.Second

// webhookError describes a failed attempt without the URL, which may hold a secret token.
func webhookError(label string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("%s failed: %w", label, err)
}

// postReport sends body to a webhook as JSON. An attempt succeeds on a 2xx answer. After a
// failure it is tried again up to retries more times, waiting 1s, 2s, 4s... between attempts.
// Each attempt may take at most timeout. Errors never contain the URL.
func postReport(rawURL string, body []byte, timeout time.Duration, retries int) error {
	label := file.WebhookLabel(rawURL)
	client := &http.Client{Timeout: timeout}
	wait := webhookBackoff
	var last error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			fmt.Printf("%s: attempt %d of %d failed (%v); retrying in %s\n", label, attempt, retries+1, last, wait)
			time.Sleep(wait)
			if wait *= 2; wait > webhookBackoffCap {
				wait = webhookBackoffCap
			}
		}
		req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
		if err != nil {
			return webhookError(label, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "ipsetfw")
		resp, err := client.Do(req)
		if err != nil {
			last = webhookError(label, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			return nil
		}
		last = fmt.Errorf("%s answered %s", label, resp.Status)
	}
	return last
}
