package notif

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SendNotificationMattermost posts message to a Mattermost incoming webhook.
// It does nothing when the URL or token is empty. It returns an error instead of exiting.
func SendNotificationMattermost(message, mattermostUrl, mattermostToken string) error {
	if mattermostToken == "" || mattermostUrl == "" {
		return nil
	}
	postBody, err := json.Marshal(map[string]string{
		"text": message,
	})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(mattermostUrl+"/hooks/"+mattermostToken, "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		// The URL contains the webhook token; drop it before the error reaches any log.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("mattermost request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("mattermost returned %s", resp.Status)
	}
	return nil
}
