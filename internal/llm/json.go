package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jsonOnlyInstruction is appended to the system prompt whenever a caller asks
// for JSON. Providers without a native JSON mode still receive the instruction.
const jsonOnlyInstruction = "Respond with a single valid JSON object and nothing else. Do not wrap the object in markdown fences and do not add commentary before or after it."

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// StripFences removes a surrounding markdown code fence from s. It accepts
// triple backticks and triple tildes, with or without a language tag, and
// leaves unfenced text untouched.
func StripFences(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return t
	}

	var fence string
	switch {
	case strings.HasPrefix(t, "```"):
		fence = "```"
	case strings.HasPrefix(t, "~~~"):
		fence = "~~~"
	default:
		return t
	}

	body := t[len(fence):]
	if nl := strings.IndexByte(body, '\n'); nl >= 0 {
		body = body[nl+1:]
		if end := strings.LastIndex(body, fence); end >= 0 {
			body = body[:end]
		}
		return strings.TrimSpace(body)
	}

	// Single-line fence such as ```json{"a":1}```.
	body = strings.TrimSpace(body)
	if end := strings.LastIndex(body, fence); end >= 0 {
		body = strings.TrimSpace(body[:end])
	}
	if i := strings.IndexAny(body, `{["`); i > 0 {
		if isFenceLanguage(strings.TrimSpace(body[:i])) {
			body = strings.TrimSpace(body[i:])
		}
	}
	return body
}

func isFenceLanguage(s string) bool {
	switch strings.ToLower(s) {
	case "json", "jsonc", "json5", "javascript", "js":
		return true
	default:
		return false
	}
}

// ExtractJSONObject returns the first balanced JSON object found in s. It
// tolerates markdown fences, leading prose and trailing commentary. Braces
// inside JSON strings are ignored.
func ExtractJSONObject(s string) ([]byte, error) {
	t := strings.TrimSpace(StripFences(s))
	if t == "" {
		return nil, errors.New("extract JSON object: empty response")
	}
	if t[0] == '{' {
		if json.Valid([]byte(t)) {
			return []byte(t), nil
		}
		// The response starts with an object: never fall back to a nested
		// object, because that would hide a malformed outer object.
		if end := scanJSONObject(t, 0); end > 0 && json.Valid([]byte(t[:end])) {
			return []byte(t[:end]), nil
		}
		return nil, errors.New("extract JSON object: response starts with an invalid JSON object")
	}

	for i := 0; i < len(t); i++ {
		if t[i] != '{' {
			continue
		}
		end := scanJSONObject(t, i)
		if end < 0 {
			continue
		}
		candidate := t[i:end]
		if json.Valid([]byte(candidate)) {
			return []byte(candidate), nil
		}
	}
	return nil, errors.New("extract JSON object: no JSON object found in response")
}

// scanJSONObject returns the index just past the closing brace of the object
// that starts at start, or -1 when the object is not balanced.
func scanJSONObject(s string, start int) int {
	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(s); i++ {
		ch := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// DecodeInto unmarshals JSON into v, tolerating a UTF-8 BOM, markdown fences
// and surrounding prose. The error names the JSON problem so callers can show
// it without dumping the whole model response.
func DecodeInto(data []byte, v any) error {
	if v == nil {
		return errors.New("decode JSON: nil destination")
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
	if len(trimmed) == 0 {
		return errors.New("decode JSON: empty input")
	}

	firstErr := json.Unmarshal(trimmed, v)
	if firstErr == nil {
		return nil
	}

	obj, extractErr := ExtractJSONObject(string(trimmed))
	if extractErr != nil {
		return fmt.Errorf("decode JSON: %w", firstErr)
	}
	if err := json.Unmarshal(obj, v); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

// withJSONInstruction appends the shared JSON-only instruction to system.
func withJSONInstruction(system string) string {
	s := strings.TrimSpace(system)
	if s == "" {
		return jsonOnlyInstruction
	}
	return s + "\n\n" + jsonOnlyInstruction
}

// withJSONSchemaInstruction appends the JSON-only instruction and, when the
// caller supplied a valid schema, the schema itself. Used by providers without
// structured-output support.
func withJSONSchemaInstruction(system string, schema json.RawMessage) string {
	instruction := jsonOnlyInstruction
	if len(schema) > 0 && json.Valid(schema) {
		instruction += " The object must conform to this JSON Schema: " + string(schema)
	}
	s := strings.TrimSpace(system)
	if s == "" {
		return instruction
	}
	return s + "\n\n" + instruction
}
