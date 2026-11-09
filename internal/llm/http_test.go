package llm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransportRetriesNetworkError(t *testing.T) {
	var calls atomic.Int32
	tr := newTransport("test", time.Second, "secret-key", discardLogger())
	tr.baseDelay = time.Millisecond
	tr.maxDelay = time.Millisecond
	tr.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("connection reset by peer")
	})

	_, err := tr.do(context.Background(), http.MethodPost, "http://example.invalid/chat", http.Header{}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) {
		t.Fatalf("error type = %T", err)
	}
	if providerErr.Status != 0 || providerErr.Code != "network" || !providerErr.Retryable {
		t.Errorf("error = %#v", providerErr)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
}

func TestTransportDoesNotRetryNon4294xx(t *testing.T) {
	var calls atomic.Int32
	tr := newTransport("test", time.Second, "secret-key", discardLogger())
	tr.baseDelay = time.Millisecond
	tr.maxDelay = time.Millisecond
	tr.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"forbidden"}}`)),
			Request:    r,
		}, nil
	})

	_, err := tr.do(context.Background(), http.MethodPost, "http://example.invalid/chat", http.Header{}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Status != http.StatusForbidden {
		t.Errorf("error = %#v", providerErr)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestTransportHonoursRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			writeBody(w, http.StatusTooManyRequests, `{"error":{"message":"slow down"}}`)
			return
		}
		writeBody(w, http.StatusOK, `{"ok":true}`)
	}))
	defer srv.Close()

	tr := newTransport("test", time.Second, "secret-key", discardLogger())
	tr.baseDelay = time.Second
	tr.maxDelay = 8 * time.Second
	var slept []time.Duration
	tr.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}

	if _, err := tr.do(context.Background(), http.MethodPost, srv.URL, http.Header{}, []byte(`{}`)); err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(slept) != 1 || slept[0] != 2*time.Second {
		t.Errorf("slept = %v, want one 2s Retry-After delay", slept)
	}
}

func TestTransportRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseBytes+1))
	}))
	defer srv.Close()

	tr := newTransport("test", time.Second, "secret-key", discardLogger())
	_, err := tr.do(context.Background(), http.MethodPost, srv.URL, http.Header{}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "response_too_large" {
		t.Errorf("error = %#v", providerErr)
	}
	if providerErr.Retryable {
		t.Error("Retryable = true, want false")
	}
}

func TestTransportCancelledContext(t *testing.T) {
	tr := newTransport("test", time.Second, "secret-key", discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := tr.do(ctx, http.MethodPost, "http://example.invalid/chat", http.Header{}, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *Error
	if !errors.As(err, &providerErr) || providerErr.Code != "canceled" {
		t.Errorf("error = %#v", providerErr)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		value  string
		want   time.Duration
		maxCap time.Duration
	}{
		{"missing", "", 0, 8 * time.Second},
		{"zero", "0", 0, 8 * time.Second},
		{"seconds", "3", 3 * time.Second, 8 * time.Second},
		{"capped", "100", 8 * time.Second, 8 * time.Second},
		{"http date", now.Add(5 * time.Second).Format(http.TimeFormat), 5 * time.Second, 8 * time.Second},
		{"past date", now.Add(-time.Minute).Format(http.TimeFormat), 0, 8 * time.Second},
		{"garbage", "soon", 0, 8 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			if tc.value != "" {
				header.Set("Retry-After", tc.value)
			}
			if got := parseRetryAfter(header, now, tc.maxCap); got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestParseProviderError(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCode string
		wantMsg  string
	}{
		{"openai", `{"error":{"message":"bad key","type":"invalid_request_error","code":"invalid_api_key"}}`, "invalid_api_key", "bad key"},
		{"anthropic", `{"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}`, "overloaded_error", "overloaded"},
		{"string error", `{"error":"plain failure"}`, "", "plain failure"},
		{"top message", `{"message":"outer message"}`, "", "outer message"},
		{"detail", `{"detail":"detail message"}`, "", "detail message"},
		{"plain text", `not json at all`, "", "not json at all"},
		{"empty", ``, "", ""},
		{"numeric code falls back to status", `{"error":{"code":400,"message":"bad","status":"INVALID_ARGUMENT"}}`, "INVALID_ARGUMENT", "bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, message := parseProviderError([]byte(tc.body))
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if message != tc.wantMsg {
				t.Errorf("message = %q, want %q", message, tc.wantMsg)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	input := `key sk-secret in https://example.test/v1?key=abc123 and header Bearer tok_987`
	got := redact(input, "sk-secret")
	for _, leaked := range []string{"sk-secret", "abc123", "tok_987"} {
		if strings.Contains(got, leaked) {
			t.Errorf("redacted string still contains %q: %s", leaked, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("redacted string = %q", got)
	}
}
