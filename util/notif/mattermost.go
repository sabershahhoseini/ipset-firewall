package notif

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/sabershahhoseini/ipset-firewall/error/checkerr"
)

func SendNotificationMattermost(message, mattermostUrl, mattermostToken string) {
	if mattermostToken == "" || mattermostUrl == "" {
		return
	}
	postBody, _ := json.Marshal(map[string]string{
		"text": message,
	})
	responseBody := bytes.NewBuffer(postBody)
	url := mattermostUrl + "/hooks/" + mattermostToken
	resp, err := http.Post(url, "application/json", responseBody)
	if err != nil {
		checkerr.Fatal(err)
	}
	defer resp.Body.Close()
}
