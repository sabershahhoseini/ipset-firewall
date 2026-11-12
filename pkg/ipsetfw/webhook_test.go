package ipsetfw

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sabershahhoseini/ipset-firewall/util/file"
)

// fastBackoff makes retries quick for a test and restores the setting afterwards.
func fastBackoff(t *testing.T) {
	t.Helper()
	prev := webhookBackoff
	webhookBackoff = 5 * time.Millisecond
	t.Cleanup(func() { webhookBackoff = prev })
}

func TestPostReportSendsJSONAndHeaders(t *testing.T) {
	var gotBody []byte
	var gotType, gotAgent, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotType, gotAgent = r.Method, r.Header.Get("Content-Type"), r.Header.Get("User-Agent")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent) // any 2xx is success
	}))
	defer srv.Close()
	rep := newReport("apply", "x.yml")
	rep.Result = "ok"
	body, _ := json.Marshal(rep)
	if err := postReport(srv.URL+"/hook/SECRET", body, 2*time.Second, 0); err != nil {
		t.Fatalf("postReport: %v", err)
	}
	if gotMethod != "POST" || gotType != "application/json" || gotAgent != "ipsetfw" {
		t.Errorf("method=%s type=%s agent=%s", gotMethod, gotType, gotAgent)
	}
	var back map[string]any
	if err := json.Unmarshal(gotBody, &back); err != nil || back["action"] != "apply" {
		t.Errorf("body = %s (%v)", gotBody, err)
	}
}

func TestPostReportRetriesAfter500(t *testing.T) {
	fastBackoff(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			http.Error(w, "busy", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := postReport(srv.URL, []byte("{}"), time.Second, 2); err != nil {
		t.Fatalf("expected success on the third attempt: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestPostReportNoRetriesByDefault(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "no", http.StatusBadGateway)
	}))
	defer srv.Close()
	err := postReport(srv.URL, []byte("{}"), time.Second, 0)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("err = %v, want a 502", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestPostReportAllAttemptsFail(t *testing.T) {
	fastBackoff(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if err := postReport(srv.URL, []byte("{}"), time.Second, 2); err == nil {
		t.Fatal("expected failure")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (1 + 2 retries)", calls)
	}
}

func TestPostReportTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	start := time.Now()
	err := postReport(srv.URL, []byte("{}"), 200*time.Millisecond, 0)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %v, want about 200ms", took)
	}
}

func TestPostReportErrorsNeverContainTheURL(t *testing.T) {
	fastBackoff(t)
	// A refused connection, a bad status, and a timeout: none may leak the path or query.
	secret := "/services/T0/B0/SECRET-TOKEN?token=SECRET2"
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	downURL := down.URL
	down.Close() // now refuses connections
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) }))
	defer bad.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }))
	defer slow.Close()

	for name, raw := range map[string]string{"refused": downURL + secret, "status": bad.URL + secret, "timeout": slow.URL + secret} {
		err := postReport(raw, []byte("{}"), 100*time.Millisecond, 1)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "services") {
			t.Errorf("%s: error leaks the URL: %v", name, err)
		}
		if !strings.Contains(err.Error(), "webhook http://127.0.0.1") {
			t.Errorf("%s: error does not name the host: %v", name, err)
		}
	}
	// A malformed URL must not leak either.
	if err := postReport("http://exa mple.com/SECRET", []byte("{}"), time.Second, 0); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("malformed URL: err = %v", err)
	}
}

func TestRunEventWebhookGetsReportAndFailureIsRecorded(t *testing.T) {
	fastBackoff(t)
	var got map[string]any
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) }))
	defer bad.Close()

	r := hookRunner{cfg: file.HooksConfig{Timeout: "2s"}, reportDir: t.TempDir()}
	rep := newReport("apply", "x.yml")
	rep.Result, rep.Changed = "ok", true
	rep.Lists = []listReport{{Kind: "block", Name: "tor", Status: "updated", Added: 3}}
	failures := r.runEvent("after", []file.Hook{{Webhook: ok.URL + "/a/SECRET"}, {Webhook: bad.URL + "/b/SECRET"}}, rep, nil)
	if got["result"] != "ok" || got["action"] != "apply" {
		t.Errorf("receiver got %v", got)
	}
	if len(failures) != 1 || failures[0].index != 2 {
		t.Fatalf("failures = %+v, want only the second webhook", failures)
	}
	if strings.Contains(failures[0].err.Error(), "SECRET") {
		t.Errorf("failure leaks the URL: %v", failures[0].err)
	}
}

func TestOnErrorOnlyRunsForFailedRunsAndNeverChangesTheResult(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "x", 500) // the onError hook itself fails
	}))
	defer srv.Close()
	r := hookRunner{cfg: file.HooksConfig{Timeout: "2s", OnError: []file.Hook{{Webhook: srv.URL}}}, reportDir: t.TempDir()}

	ok := newReport("apply", "x.yml")
	ok.Result = "ok"
	r.onError(ok)
	if calls != 0 {
		t.Error("onError ran for a successful run")
	}
	failed := newReport("apply", "x.yml")
	failed.Result = "failed"
	r.onError(failed)
	if calls != 1 {
		t.Errorf("onError calls = %d, want 1", calls)
	}
	if failed.Result != "failed" || len(failed.HookFailures) != 1 {
		t.Errorf("result=%s hookFailures=%v", failed.Result, failed.HookFailures)
	}
}
