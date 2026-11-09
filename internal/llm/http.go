package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/version"
)

const (
	// maxResponseBytes bounds how much of a provider response is read.
	maxResponseBytes = 4 << 20
	defaultTimeout   = 120 * time.Second
	maxRetries       = 2
	backoffBase      = 500 * time.Millisecond
	backoffCap       = 8 * time.Second
)

var (
	errResponseTooLarge = errors.New("response body exceeds 4 MiB")

	// querySecretPattern catches API keys that end up in an error message as
	// part of a URL query string (Gemini puts the key there).
	querySecretPattern = regexp.MustCompile(`(?i)([?&](key|api_key|api-key|access_token|token)=)[^&\s"'<>]+`)
	bearerPattern      = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
	userInfoPattern    = regexp.MustCompile(`(?i)(https?://)[^/@\s"'<>]+@`)
)

// transport is the shared HTTP layer for every provider. It owns one
// http.Client, applies the retry policy and converts every failure into a
// typed *Error with secrets removed.
type transport struct {
	provider string
	client   *http.Client
	secrets  []string
	logger   *slog.Logger

	baseDelay time.Duration
	maxDelay  time.Duration
	retries   int
	sleep     func(context.Context, time.Duration) error
}

func newTransport(provider string, timeout time.Duration, apiKey string, logger *slog.Logger) *transport {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	t := &transport{
		provider:  provider,
		client:    &http.Client{Timeout: timeout},
		logger:    logger,
		baseDelay: backoffBase,
		maxDelay:  backoffCap,
		retries:   maxRetries,
		sleep:     sleepContext,
	}
	if apiKey != "" {
		t.secrets = append(t.secrets, apiKey)
	}
	return t
}

// do performs one logical request, retrying retryable statuses and transport
// errors up to t.retries times.
func (t *transport) do(ctx context.Context, method, rawURL string, headers http.Header, body []byte) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, t.contextError(err)
		}

		req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
		if err != nil {
			return nil, t.newError(0, "request", err.Error(), false)
		}
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		resp, err := t.client.Do(req)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, t.contextError(ctxErr)
			}
			if attempt < t.retries {
				delay := t.backoff(attempt)
				t.logRetry(attempt, 0, delay)
				if sleepErr := t.sleep(ctx, delay); sleepErr != nil {
					return nil, t.contextError(sleepErr)
				}
				continue
			}
			return nil, t.transportError(err)
		}

		data, readErr := readLimited(resp.Body)
		_ = resp.Body.Close()

		if readErr != nil {
			if errors.Is(readErr, errResponseTooLarge) {
				return nil, t.newError(0, "response_too_large", readErr.Error(), false)
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, t.contextError(ctxErr)
			}
			if attempt < t.retries {
				delay := t.backoff(attempt)
				t.logRetry(attempt, 0, delay)
				if sleepErr := t.sleep(ctx, delay); sleepErr != nil {
					return nil, t.contextError(sleepErr)
				}
				continue
			}
			return nil, t.transportError(readErr)
		}

		if resp.StatusCode >= http.StatusOK && resp.StatusCode <= 299 {
			return data, nil
		}

		providerErr := t.statusError(resp.StatusCode, data)
		if !providerErr.Retryable || attempt >= t.retries {
			return nil, providerErr
		}

		delay := t.backoff(attempt)
		if retryAfter := parseRetryAfter(resp.Header, time.Now(), t.maxDelay); retryAfter > 0 {
			delay = retryAfter
		}
		t.logRetry(attempt, resp.StatusCode, delay)
		if sleepErr := t.sleep(ctx, delay); sleepErr != nil {
			return nil, t.contextError(sleepErr)
		}
	}
}

func (t *transport) logRetry(attempt, status int, delay time.Duration) {
	if t.logger == nil {
		return
	}
	// Deliberately no URL, headers or body: those can contain secrets or the
	// prompt. Provider and status are enough to debug a retry.
	t.logger.Debug("llm: retrying request",
		"provider", t.provider,
		"attempt", attempt+1,
		"status", status,
		"delay", delay.String())
}

// backoff returns an exponentially growing delay with jitter. attempt is
// zero-based, so the first retry waits between baseDelay/2 and baseDelay.
func (t *transport) backoff(attempt int) time.Duration {
	base := t.baseDelay
	if base <= 0 {
		base = backoffBase
	}
	maxDelay := t.maxDelay
	if maxDelay <= 0 {
		maxDelay = backoffCap
	}

	d := base
	for i := 0; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	if d > maxDelay {
		d = maxDelay
	}

	half := d / 2
	if half <= 0 {
		return d
	}
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func (t *transport) statusError(status int, body []byte) *Error {
	code, message := parseProviderError(body)
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(status)
	}
	if strings.TrimSpace(message) == "" {
		message = "request failed"
	}
	return t.newError(status, code, message, retryableStatus(status))
}

func (t *transport) transportError(err error) *Error {
	code := "network"
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		code = "timeout"
	}
	return t.newError(0, code, err.Error(), true)
}

func (t *transport) contextError(err error) *Error {
	if errors.Is(err, context.DeadlineExceeded) {
		return t.newError(0, "timeout", "request timed out: "+err.Error(), false)
	}
	return t.newError(0, "canceled", "request canceled: "+err.Error(), false)
}

func (t *transport) newError(status int, code, message string, retryable bool) *Error {
	message = strings.TrimSpace(singleLine(message))
	if message == "" {
		message = "request failed"
	}
	return &Error{
		Provider:  t.provider,
		Status:    status,
		Code:      redact(code, t.secrets...),
		Message:   TruncateText(redact(message, t.secrets...), 600),
		Retryable: retryable,
	}
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, errResponseTooLarge
	}
	return data, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// parseRetryAfter honours the Retry-After header, bounded by limit so a
// provider cannot stall a scan indefinitely.
func parseRetryAfter(header http.Header, now time.Time, limit time.Duration) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if limit <= 0 {
		limit = backoffCap
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		d := time.Duration(seconds) * time.Second
		if d > limit {
			d = limit
		}
		return d
	}
	if when, err := http.ParseTime(value); err == nil {
		d := when.Sub(now)
		if d <= 0 {
			return 0
		}
		if d > limit {
			d = limit
		}
		return d
	}
	return 0
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// redact removes known API keys and common key-shaped substrings from s.
func redact(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, "[REDACTED]")
	}
	s = userInfoPattern.ReplaceAllString(s, "${1}[REDACTED]@")
	s = querySecretPattern.ReplaceAllString(s, "${1}[REDACTED]")
	s = bearerPattern.ReplaceAllString(s, "${1}[REDACTED]")
	return s
}

// parseProviderError defensively extracts a code and message from a provider
// error body. It understands {"error":{"message":…,"type":…}}, {"error":"…"},
// {"message":…}, {"detail":…} and plain text.
func parseProviderError(raw []byte) (code, message string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", ""
	}

	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Detail  string          `json:"detail"`
		Type    string          `json:"type"`
		Code    json.RawMessage `json:"code"`
		Status  string          `json:"status"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil {
		if len(envelope.Error) > 0 && !isJSONNull(envelope.Error) {
			code, message = parseErrorValue(envelope.Error)
		}
		if strings.TrimSpace(message) == "" {
			message = firstNonEmpty(envelope.Message, envelope.Detail)
		}
		if strings.TrimSpace(code) == "" {
			code = firstNonEmpty(rawScalar(envelope.Code), envelope.Type, envelope.Status)
		}
		if strings.TrimSpace(message) != "" {
			return code, message
		}
	}

	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return "", plain
	}
	return "", singleLine(string(raw))
}

func parseErrorValue(raw json.RawMessage) (code, message string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || isJSONNull(raw) {
		return "", ""
	}

	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return "", plain
	}

	var object struct {
		Message string          `json:"message"`
		Detail  string          `json:"detail"`
		Type    string          `json:"type"`
		Status  string          `json:"status"`
		Code    json.RawMessage `json:"code"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		code = firstNonEmpty(rawScalar(object.Code), object.Type, object.Status)
		message = firstNonEmpty(object.Message, object.Detail, object.Type)
		return code, message
	}
	return "", singleLine(string(raw))
}

// rawScalar returns a JSON string value, or "" for numbers, objects and
// arrays. Provider codes are useful when they are strings; numeric codes are
// not worth surfacing as a code.
func rawScalar(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || isJSONNull(raw) {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

func isJSONNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func singleLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func isHTTPStatus(err error, status int) bool {
	var providerErr *Error
	return errors.As(err, &providerErr) && providerErr.Status == status
}

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}

func userAgent() string {
	v := strings.TrimSpace(version.Version)
	if v == "" {
		v = "dev"
	}
	return "lv24-vigil/" + v
}

// normalizeMessages prepends the system prompt and drops messages with empty
// content, which providers reject.
func normalizeMessages(system string, messages []Message) []Message {
	out := make([]Message, 0, len(messages)+1)
	if strings.TrimSpace(system) != "" {
		out = append(out, Message{Role: RoleSystem, Content: system})
	}
	for _, message := range messages {
		if strings.TrimSpace(message.Content) == "" {
			continue
		}
		role := message.Role
		if role == "" {
			role = RoleUser
		}
		out = append(out, Message{Role: role, Content: message.Content})
	}
	return out
}

func clampFloat(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func encodeRequest(provider string, v any) ([]byte, *Error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, &Error{
			Provider: provider,
			Code:     "encode_request",
			Message:  fmt.Sprintf("encode request: %v", err),
		}
	}
	return body, nil
}
