package llm

import (
	"strings"
	"testing"
)

func TestStripFences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", `{"a":1}`, `{"a":1}`},
		{"fenced json", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{"fenced plain", "```\n{\"a\":1}\n```", `{"a":1}`},
		{"tilde fence", "~~~json\n{\"a\":1}\n~~~", `{"a":1}`},
		{"single line", "```json{\"a\":1}```", `{"a":1}`},
		{"surrounding spaces", "  ```json\n{}\n```  ", "{}"},
		{"unclosed", "```json\n{}", "{}"},
		{"empty", "", ""},
		{"no fence", "  hello  ", "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripFences(tc.in); got != tc.want {
				t.Errorf("StripFences(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractJSONObject(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", `{"a":1}`, `{"a":1}`},
		{"fenced", "```json\n{\"a\":1}\n```", `{"a":1}`},
		{"leading prose", `Here you go: {"a":1}`, `{"a":1}`},
		{"prose braces", `Use {curly} braces: {"a":1}`, `{"a":1}`},
		{"nested", `{"a":{"b":"}"},"c":[1,2]}`, `{"a":{"b":"}"},"c":[1,2]}`},
		{"string braces", `{"a":"}{"}`, `{"a":"}{"}`},
		{"trailing text", `{"a":1} thanks`, `{"a":1}`},
		{"fenced with prose", "Here:\n```json\n{\"a\":1}\n```\nDone", `{"a":1}`},
		{"whitespace", " \n\t{\"a\":1}\n ", `{"a":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractJSONObject(tc.in)
			if err != nil {
				t.Fatalf("ExtractJSONObject(%q): %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractJSONObjectErrors(t *testing.T) {
	for _, in := range []string{
		"",
		"no json here",
		"[1,2,3]",
		`{"unbalanced":`,
		`{"a":{"b":1},}`,
		`{"a":{"b":1}`,
	} {
		if _, err := ExtractJSONObject(in); err == nil {
			t.Errorf("ExtractJSONObject(%q) returned no error", in)
		}
	}
}

func TestDecodeInto(t *testing.T) {
	type payload struct {
		A int `json:"a"`
	}

	cases := []struct {
		name string
		in   string
		want int
	}{
		{"plain", `{"a":1}`, 1},
		{"fenced", "```json\n{\"a\":2}\n```", 2},
		{"prose", `prefix {"a":3} suffix`, 3},
		{"bom", "\uFEFF{\"a\":4}", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got payload
			if err := DecodeInto([]byte(tc.in), &got); err != nil {
				t.Fatalf("DecodeInto: %v", err)
			}
			if got.A != tc.want {
				t.Errorf("A = %d, want %d", got.A, tc.want)
			}
		})
	}
}

func TestDecodeIntoErrors(t *testing.T) {
	var out map[string]any
	if err := DecodeInto([]byte(`{"a":`), &out); err == nil {
		t.Fatal("expected error for malformed JSON")
	} else if !strings.Contains(err.Error(), "decode JSON") {
		t.Errorf("error = %v, want decode context", err)
	}

	if err := DecodeInto(nil, &out); err == nil {
		t.Fatal("expected error for empty input")
	}
	if err := DecodeInto([]byte(`{}`), nil); err == nil {
		t.Fatal("expected error for nil destination")
	}
}
