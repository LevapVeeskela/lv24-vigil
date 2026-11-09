package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/levapveeskela/lv24-vigil/internal/version"
)

const (
	// precheckDefaultAPI is the local LV24 security control plane. Through the
	// edge use https://lv24.by/api (same origin as the staff SPA).
	precheckDefaultAPI = "http://localhost:3791"
	precheckEndpoint   = "/security-scans/prechecks"
	precheckToolName   = "vigil"

	// precheckMaxSARIFBytes mirrors the control-plane cap: an oversized document
	// is rejected locally instead of spending an upload on it.
	precheckMaxSARIFBytes = 10 << 20
	// precheckMaxErrorBytes bounds how much of an API error body we echo.
	precheckMaxErrorBytes = 2 << 10
	// precheckMaxResponseBytes bounds the success body we are willing to parse.
	precheckMaxResponseBytes = 4 << 20

	precheckTimeout = 30 * time.Second

	// precheckTokenEnv is the fallback for --token, so CI can keep the JWT out
	// of the command line and the process list.
	precheckTokenEnv = "VIGIL_SECURITY_API_TOKEN"
)

// precheckRequest is the control-plane envelope. The SARIF document stays raw
// so the bytes the scanner produced are uploaded verbatim.
type precheckRequest struct {
	Target      string          `json:"target"`
	Commit      string          `json:"commit,omitempty"`
	Tool        string          `json:"tool"`
	ToolVersion string          `json:"toolVersion,omitempty"`
	SARIF       json.RawMessage `json:"sarif"`
}

// precheckResponse is the 201 body. Only the fields the CLI prints are typed;
// the control plane may add more.
type precheckResponse struct {
	ID        string          `json:"id"`
	CreatedAt string          `json:"createdAt"`
	Summary   precheckSummary `json:"summary"`
}

type precheckSummary struct {
	Total   int `json:"total"`
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Note    int `json:"note"`
}

// runPrecheck uploads one SARIF report as a pre-check record. It never starts a
// scan: the control plane stores evidence only.
func runPrecheck(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("precheck")
	sarifPath := fs.String("sarif", "", "SARIF 2.1.0 file to upload")
	api := fs.String("api", precheckDefaultAPI, "control-plane base URL")
	token := fs.String("token", "", "staff JWT with ops:security-scans (or "+precheckTokenEnv+")")
	target := fs.String("target", "", "target identifier, for example $GITHUB_REPOSITORY")
	commit := fs.String("commit", "", "commit SHA the report describes")
	toolVersion := fs.String("tool-version", version.Version, "tool version recorded with the pre-check")
	asJSON := fs.Bool("json", false, "print the API response as JSON")

	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printPrecheckUsage(stdout)
		return nil
	}
	if err != nil {
		return fmt.Errorf("precheck: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("precheck takes no arguments (got %q); use --sarif FILE", positional[0])
	}

	targetValue := strings.TrimSpace(*target)
	if targetValue == "" {
		return errors.New("precheck: --target is required (for example $GITHUB_REPOSITORY)")
	}
	pathValue := strings.TrimSpace(*sarifPath)
	if pathValue == "" {
		return errors.New("precheck: --sarif is required (make one with `vigil scan --format sarif --output vigil.sarif`)")
	}
	tokenValue := strings.TrimSpace(*token)
	if tokenValue == "" {
		tokenValue = strings.TrimSpace(os.Getenv(precheckTokenEnv))
	}
	if tokenValue == "" {
		return fmt.Errorf("precheck: a staff JWT is required; pass --token or set %s", precheckTokenEnv)
	}

	data, err := readPrecheckSARIF(pathValue, precheckMaxSARIFBytes)
	if err != nil {
		return err
	}
	if err := validatePrecheckSARIF(data); err != nil {
		return fmt.Errorf("precheck: %s: %w", pathValue, err)
	}
	endpoint, err := precheckURL(*api)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(precheckRequest{
		Target:      targetValue,
		Commit:      strings.TrimSpace(*commit),
		Tool:        precheckToolName,
		ToolVersion: strings.TrimSpace(*toolVersion),
		SARIF:       json.RawMessage(data),
	})
	if err != nil {
		return fmt.Errorf("precheck: encode request: %w", err)
	}

	ctx, stop := signalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("precheck: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenValue)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vigil/"+strings.TrimSpace(version.Version))

	client := &http.Client{Timeout: precheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("precheck: %s: %s", endpoint, redactSecret(err.Error(), tokenValue))
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, precheckMaxResponseBytes+1))
	if readErr != nil {
		return fmt.Errorf("precheck: read response: %w", readErr)
	}
	truncated := len(body) > precheckMaxResponseBytes
	if truncated {
		body = body[:precheckMaxResponseBytes]
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return precheckAPIError(resp.StatusCode, body, tokenValue)
	}
	if *asJSON && truncated {
		return fmt.Errorf("precheck: response exceeds %d bytes; drop --json", precheckMaxResponseBytes)
	}

	if *asJSON {
		return writePrecheckJSON(stdout, body)
	}

	var parsed precheckResponse
	if err := json.Unmarshal(body, &parsed); err != nil || strings.TrimSpace(parsed.ID) == "" {
		// The upload succeeded; a surprising body must not turn it into a failure.
		fmt.Fprintf(stdout, "precheck uploaded: HTTP %d\n", resp.StatusCode)
		return nil
	}
	fmt.Fprintf(stdout, "precheck %s created: %d error / %d warning / %d note\n",
		parsed.ID, parsed.Summary.Error, parsed.Summary.Warning, parsed.Summary.Note)
	return nil
}

// precheckURL joins the configured base with the pre-check route. A trailing
// slash is tolerated so `--api http://localhost:3791/` works.
func precheckURL(api string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(api), "/")
	if base == "" {
		return "", errors.New("precheck: --api is empty (use " + precheckDefaultAPI + " or https://lv24.by/api)")
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("precheck: --api %q: %w", api, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("precheck: --api %q needs an http:// or https:// scheme", api)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("precheck: --api %q has no host", api)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("precheck: --api %q must not carry a query or fragment", api)
	}
	return base + precheckEndpoint, nil
}

// readPrecheckSARIF reads the report with a hard cap. The stat check gives a
// clear message for the common case; the limited read covers a file that grows
// between the stat and the read.
func readPrecheckSARIF(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("precheck: read %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("precheck: read %s: is a directory", path)
	}
	if limit > 0 && info.Size() > limit {
		return nil, fmt.Errorf("precheck: %s is %d bytes; the SARIF cap is %d bytes", path, info.Size(), limit)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("precheck: read %s: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("precheck: read %s: %w", path, err)
	}
	if limit > 0 && int64(len(data)) > limit {
		return nil, fmt.Errorf("precheck: %s exceeds the %d byte SARIF cap", path, limit)
	}
	// Windows PowerShell writes a UTF-8 BOM with `Set-Content -Encoding utf8`.
	// Both Go JSON decoders reject it, so drop the marker here and upload the
	// document without it.
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}), nil
}

// validatePrecheckSARIF applies the cheap subset the control plane requires, so
// a broken report fails here instead of after an upload. It does not duplicate
// the full server-side validation.
func validatePrecheckSARIF(data []byte) error {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("sarif is not a JSON object: %w", err)
	}

	version, _ := doc["version"].(string)
	version = strings.TrimSpace(version)
	if !strings.HasPrefix(version, "2.1.") {
		if version == "" {
			return errors.New("sarif.version is missing; the control plane accepts 2.1.x only")
		}
		return fmt.Errorf("sarif.version = %q; the control plane accepts 2.1.x only", version)
	}

	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		return errors.New("sarif.runs must be a non-empty array")
	}
	return nil
}

// precheckAPIError echoes the bounded API body. The token is stripped as a
// precaution: it must never reach stdout, stderr or a CI log.
func precheckAPIError(status int, body []byte, token string) error {
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("precheck: HTTP %d from the control plane", status)
	}
	msg = redactSecret(msg, token)
	if len(msg) > precheckMaxErrorBytes {
		msg = strings.ToValidUTF8(msg[:precheckMaxErrorBytes], "") + "…"
	}
	return fmt.Errorf("precheck: HTTP %d: %s", status, msg)
}

// writePrecheckJSON re-indents the API body without re-encoding it, so the
// printed document matches what the control plane returned.
func writePrecheckJSON(w io.Writer, body []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		buf.Reset()
		buf.Write(bytes.TrimSpace(body))
	}
	buf.WriteByte('\n')
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("precheck: write response: %w", err)
	}
	return nil
}

func redactSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}

func printPrecheckUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: vigil precheck --sarif FILE --target TARGET [flags]

Uploads a Vigil SARIF 2.1.0 report to the LV24 security control plane as a
pre-check record. It does not start a scan: the control plane stores the
evidence only.

Flags:
  --sarif FILE           SARIF 2.1.0 file to upload (required, max 10 MiB)
  --target TARGET        target identifier, for example $GITHUB_REPOSITORY (required)
  --api URL              control-plane base URL (default `+precheckDefaultAPI+`)
                         use https://lv24.by/api through the LV24 edge
  --token JWT            staff JWT with ops:security-scans (never printed)
  --commit SHA           commit the report describes
  --tool-version V       tool version recorded with the pre-check
  --json                 print the API response as JSON

Environment:
  `+precheckTokenEnv+`  fallback for --token
`)
}
