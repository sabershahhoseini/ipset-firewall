package netutils

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func serve(t *testing.T, status int, body string, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchFromSourcesFallsBackOnHTTPError(t *testing.T) {
	var primaryHits, fallbackHits int32
	primary := serve(t, http.StatusNotFound, "not found", &primaryHits)
	body := "10.0.0.0/25\n10.0.0.128/25\n"
	fallback := serve(t, http.StatusOK, body, &fallbackHits)

	got, err := fetchFromSources([]string{primary.URL, fallback.URL}, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := MergeIPsToCIDRs(strings.Split(body, "\n")); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Errorf("hits primary=%d fallback=%d, want 1 and 1", primaryHits, fallbackHits)
	}
}

func TestFetchFromSourcesFallsBackOnEmptyResult(t *testing.T) {
	// 200 OK but no usable lines: must not be accepted as a successful, empty pool.
	empty := serve(t, http.StatusOK, "# comment only\n\ngarbage\n", nil)
	fallback := serve(t, http.StatusOK, "192.0.2.1\n", nil)

	got, err := fetchFromSources([]string{empty.URL, fallback.URL}, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"192.0.2.1/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFetchFromSourcesUsesFirstWorkingSourceOnly(t *testing.T) {
	var fallbackHits int32
	primary := serve(t, http.StatusOK, "192.0.2.1\n", nil)
	fallback := serve(t, http.StatusOK, "198.51.100.1\n", &fallbackHits)

	got, err := fetchFromSources([]string{primary.URL, fallback.URL}, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"192.0.2.1/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if fallbackHits != 0 {
		t.Errorf("fallback was contacted %d times, want 0", fallbackHits)
	}
}

func TestFetchFromSourcesAllFail(t *testing.T) {
	a := serve(t, http.StatusInternalServerError, "", nil)
	b := serve(t, http.StatusOK, "", nil)

	_, err := fetchFromSources([]string{a.URL, b.URL}, false, "")
	if err == nil {
		t.Fatal("expected an error when every source fails")
	}
	msg := err.Error()
	if !strings.Contains(msg, "500") || !strings.Contains(msg, "no valid networks from "+b.URL) {
		t.Errorf("error does not name each failure: %v", err)
	}
}
