// Package config resolves Vigil's configuration from defaults, a user config
// file, a project config file and environment variables, in that order.
//
// Secrets are read from the environment or the user config file only. A project
// file is committed to git, so it may not contain an API key.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/levapveeskela/lv24-vigil/internal/model"
	"github.com/levapveeskela/lv24-vigil/internal/safepath"
)

// Provider names understood by the LLM factory.
const (
	ProviderOpenAI     = "openai"
	ProviderAnthropic  = "anthropic"
	ProviderGemini     = "gemini"
	ProviderOpenRouter = "openrouter"
	ProviderGroq       = "groq"
	ProviderDeepSeek   = "deepseek"
	ProviderMistral    = "mistral"
	ProviderXAI        = "xai"
	ProviderOllama     = "ollama"
	ProviderLMStudio   = "lmstudio"
	ProviderCustom     = "custom"
	// ProviderOpenCodeGo is the OpenAI-compatible OpenCode Go inference
	// endpoint (https://opencode.ai/inference/go/openai/v1). It is a hosted
	// subscription: the user supplies their own OpenCode Go key.
	ProviderOpenCodeGo = "opencode-go"
	// ProviderOpenCode is accepted as a short alias for ProviderOpenCodeGo.
	ProviderOpenCode = "opencode"
	// ProviderCommand runs a local CLI that already has its own authentication
	// (for example `opencode run`) and reads the completion from its stdout.
	// It stores no API key and never talks to the network itself.
	ProviderCommand = "command"
)

// Command provider settings.
const (
	CommandPromptArg   = "arg"
	CommandPromptStdin = "stdin"

	CommandOutputAuto         = "auto"
	CommandOutputText         = "text"
	CommandOutputOpenCodeJSON = "opencode-json"

	// DefaultCommandModel is the free-form label shown when the command
	// provider is configured without a model.
	DefaultCommandModel = "command"
	// DefaultCommandMaxOutputBytes bounds stdout by default (4 MiB).
	DefaultCommandMaxOutputBytes = 4 << 20
	// MaxCommandMaxOutputBytes is the largest accepted stdout cap (16 MiB).
	MaxCommandMaxOutputBytes = 16 << 20
)

// DefaultModel is used when a provider is configured without a model.
const DefaultModel = "gpt-4.1-mini"

// maxConfigBytes bounds a config file before it is read into memory. A hostile
// repository must not be able to make `vigil scan` allocate an arbitrary file.
const maxConfigBytes = 1 << 20

// Config is the fully resolved runtime configuration.
type Config struct {
	Provider    string        `yaml:"provider"`
	Model       string        `yaml:"model"`
	BaseURL     string        `yaml:"base_url"`
	APIKey      string        `yaml:"api_key"`
	MaxTokens   int           `yaml:"max_tokens"`
	Temperature float64       `yaml:"temperature"`
	Timeout     time.Duration `yaml:"timeout"`
	MaxSteps    int           `yaml:"max_steps"`
	Scan        ScanConfig    `yaml:"scan"`
	Output      OutputConfig  `yaml:"output"`
	// Command provider settings. They are user-config/env only: a committed
	// project file must not be able to run arbitrary commands.
	Command               []string          `yaml:"command"`
	CommandPromptMode     string            `yaml:"command_prompt_mode"`
	CommandOutput         string            `yaml:"command_output"`
	CommandTimeout        time.Duration     `yaml:"command_timeout"`
	CommandMaxOutputBytes int               `yaml:"command_max_output_bytes"`
	CommandEnv            map[string]string `yaml:"command_env"`
	// Sources records where each value came from, for `vigil status`.
	Sources map[string]string `yaml:"-"`
	// ConfigFiles lists the files that were merged, in order.
	ConfigFiles []string `yaml:"-"`
}

// ScanConfig holds scanning defaults.
type ScanConfig struct {
	Mode         string   `yaml:"mode"`
	MinSeverity  string   `yaml:"min_severity"`
	MaxFindings  int      `yaml:"max_findings"`
	Concurrency  int      `yaml:"concurrency"`
	Exclude      []string `yaml:"exclude"`
	Include      []string `yaml:"include"`
	DisableRules []string `yaml:"disable_rules"`
	UseLLM       *bool    `yaml:"use_llm"`
	DeepReview   bool     `yaml:"deep_review"`
	MaxFileBytes int64    `yaml:"max_file_bytes"`
	FollowLinks  bool     `yaml:"follow_symlinks"`
	Baseline     string   `yaml:"baseline"`
	// OSV enables optional dependency lookups against api.osv.dev. Off by
	// default: a security tool should not phone home unless asked.
	OSV bool `yaml:"osv"`
	// OSVBaseURL overrides the OSV API endpoint (self-hosted mirror or tests).
	OSVBaseURL string `yaml:"osv_base_url"`
}

// OutputConfig holds report defaults.
type OutputConfig struct {
	Format  string `yaml:"format"` // md | json | sarif | html
	Path    string `yaml:"path"`
	Color   string `yaml:"color"` // auto | always | never
	ShowFix bool   `yaml:"show_fix"`
}

// FileConfig is the on-disk schema. Pointer fields distinguish "unset" from a
// deliberate zero value while merging.
type FileConfig struct {
	Provider    *string     `yaml:"provider"`
	Model       *string     `yaml:"model"`
	BaseURL     *string     `yaml:"base_url"`
	APIKey      *string     `yaml:"api_key"`
	MaxTokens   *int        `yaml:"max_tokens"`
	Temperature *float64    `yaml:"temperature"`
	Timeout     *string     `yaml:"timeout"`
	MaxSteps    *int        `yaml:"max_steps"`
	Scan        *ScanFile   `yaml:"scan"`
	Output      *OutputFile `yaml:"output"`
	// Command provider settings. A project file may not set the executable,
	// its environment or its output handling; only the user config and the
	// environment may do that.
	Command               []string          `yaml:"command"`
	CommandPromptMode     *string           `yaml:"command_prompt_mode"`
	CommandOutput         *string           `yaml:"command_output"`
	CommandTimeout        *string           `yaml:"command_timeout"`
	CommandMaxOutputBytes *int              `yaml:"command_max_output_bytes"`
	CommandEnv            map[string]string `yaml:"command_env"`
}

type ScanFile struct {
	Mode         *string  `yaml:"mode"`
	MinSeverity  *string  `yaml:"min_severity"`
	MaxFindings  *int     `yaml:"max_findings"`
	Concurrency  *int     `yaml:"concurrency"`
	Exclude      []string `yaml:"exclude"`
	Include      []string `yaml:"include"`
	DisableRules []string `yaml:"disable_rules"`
	UseLLM       *bool    `yaml:"use_llm"`
	DeepReview   *bool    `yaml:"deep_review"`
	MaxFileBytes *int64   `yaml:"max_file_bytes"`
	FollowLinks  *bool    `yaml:"follow_symlinks"`
	Baseline     *string  `yaml:"baseline"`
	OSV          *bool    `yaml:"osv"`
	OSVBaseURL   *string  `yaml:"osv_base_url"`
}

type OutputFile struct {
	Format  *string `yaml:"format"`
	Path    *string `yaml:"path"`
	Color   *string `yaml:"color"`
	ShowFix *bool   `yaml:"show_fix"`
}

// Defaults returns the built-in configuration.
func Defaults() Config {
	return Config{
		Provider:              "",
		Model:                 "",
		MaxTokens:             4096,
		Temperature:           0.1,
		Timeout:               120 * time.Second,
		MaxSteps:              12,
		CommandPromptMode:     CommandPromptArg,
		CommandOutput:         CommandOutputAuto,
		CommandMaxOutputBytes: DefaultCommandMaxOutputBytes,
		Scan: ScanConfig{
			Mode:         "standard",
			MinSeverity:  string(model.SeverityLow),
			MaxFindings:  200,
			Concurrency:  defaultConcurrency(),
			Exclude:      defaultExcludes(),
			MaxFileBytes: 2 << 20,
			Baseline:     ".vigil-baseline.json",
		},
		Output: OutputConfig{
			Format:  "md",
			Color:   "auto",
			ShowFix: true,
		},
		Sources: map[string]string{},
	}
}

func defaultConcurrency() int {
	n := runtime.NumCPU()
	if n < 1 {
		return 1
	}
	if n > 16 {
		return 16
	}
	return n
}

func defaultExcludes() []string {
	return []string{
		".git/**", "node_modules/**", "vendor/**", "dist/**", "build/**",
		"target/**", ".venv/**", "venv/**", "__pycache__/**", ".next/**",
		".nuxt/**", "coverage/**", ".idea/**", ".vscode/**",
		"*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json",
		"pnpm-lock.yaml", "yarn.lock", "go.sum", "Cargo.lock",
		"*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.svg",
		"*.pdf", "*.zip", "*.gz", "*.tar", "*.tgz", "*.7z", "*.exe",
		"*.dll", "*.so", "*.dylib", "*.wasm", "*.woff", "*.woff2", "*.ttf",
		".vigil/**",
	}
}

// Load resolves configuration for root. A missing config file is not an error.
func Load(root string) (Config, error) {
	cfg := Defaults()

	userPath, err := UserConfigPath()
	if err == nil {
		if err := mergeFile(&cfg, userPath, true); err != nil {
			return cfg, err
		}
	}
	if root != "" {
		for _, name := range []string{".vigil.yaml", ".vigil.yml", "vigil.yaml"} {
			path, err := safepath.Resolve(root, name)
			if err != nil {
				return cfg, fmt.Errorf("config %s: %w", name, err)
			}
			if multi, lerr := safepath.HasMultipleLinks(path); lerr == nil && multi {
				return cfg, fmt.Errorf("config %s: hardlinked project config files are not accepted", name)
			}
			if err := mergeFile(&cfg, path, false); err != nil {
				return cfg, err
			}
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// UserConfigPath returns the platform config path, honouring VIGIL_CONFIG.
func UserConfigPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("VIGIL_CONFIG")); p != "" {
		return p, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "vigil", "config.yaml"), nil
}

func mergeFile(cfg *Config, path string, allowSecret bool) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("config %s is not a regular file", path)
	}
	if info.Size() > maxConfigBytes {
		return fmt.Errorf("config %s is larger than %d bytes", path, maxConfigBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	if !allowSecret {
		if fc.APIKey != nil && strings.TrimSpace(*fc.APIKey) != "" {
			return fmt.Errorf("config %s: api_key must live in the user config or the environment, not in a project file", path)
		}
		// A project file is committed by whoever owns the repository. It must
		// not be able to redirect model traffic (and the user's key) to an
		// arbitrary endpoint or write outside the project tree.
		if fc.BaseURL != nil && strings.TrimSpace(*fc.BaseURL) != "" {
			return fmt.Errorf("config %s: base_url must live in the user config or the environment, not in a project file", path)
		}
		// The command provider executes a local process. A committed file must
		// never be able to choose that process, its environment or how its
		// output is interpreted: cloning a repository must not run code.
		if fc.Command != nil {
			return fmt.Errorf("config %s: command must live in the user config or the environment, not in a project file", path)
		}
		if fc.CommandEnv != nil {
			return fmt.Errorf("config %s: command_env must live in the user config or the environment, not in a project file", path)
		}
		if fc.CommandPromptMode != nil {
			return fmt.Errorf("config %s: command_prompt_mode must live in the user config or the environment, not in a project file", path)
		}
		if fc.CommandOutput != nil {
			return fmt.Errorf("config %s: command_output must live in the user config or the environment, not in a project file", path)
		}
		if fc.Output != nil && fc.Output.Path != nil {
			if err := validateProjectPath("output.path", *fc.Output.Path); err != nil {
				return fmt.Errorf("config %s: %w", path, err)
			}
		}
		if fc.Scan != nil {
			if fc.Scan.Baseline != nil {
				if err := validateProjectPath("scan.baseline", *fc.Scan.Baseline); err != nil {
					return fmt.Errorf("config %s: %w", path, err)
				}
			}
			if fc.Scan.FollowLinks != nil && *fc.Scan.FollowLinks {
				return fmt.Errorf("config %s: scan.follow_symlinks may only be enabled in the user config", path)
			}
		}
	}
	cfg.ConfigFiles = append(cfg.ConfigFiles, path)
	merge(&cfg.Provider, fc.Provider, "provider", path, cfg.Sources)
	merge(&cfg.Model, fc.Model, "model", path, cfg.Sources)
	merge(&cfg.BaseURL, fc.BaseURL, "base_url", path, cfg.Sources)
	if allowSecret {
		merge(&cfg.APIKey, fc.APIKey, "api_key", path, cfg.Sources)
	}
	mergeInt(&cfg.MaxTokens, fc.MaxTokens, "max_tokens", path, cfg.Sources)
	mergeFloat(&cfg.Temperature, fc.Temperature, "temperature", path, cfg.Sources)
	mergeInt(&cfg.MaxSteps, fc.MaxSteps, "max_steps", path, cfg.Sources)
	if fc.Timeout != nil {
		d, err := time.ParseDuration(*fc.Timeout)
		if err != nil {
			return fmt.Errorf("config %s: timeout: %w", path, err)
		}
		cfg.Timeout = d
		cfg.Sources["timeout"] = path
	}
	if fc.CommandTimeout != nil {
		d, err := time.ParseDuration(*fc.CommandTimeout)
		if err != nil {
			return fmt.Errorf("config %s: command_timeout: %w", path, err)
		}
		cfg.CommandTimeout = d
		cfg.Sources["command_timeout"] = path
	}
	mergeInt(&cfg.CommandMaxOutputBytes, fc.CommandMaxOutputBytes, "command_max_output_bytes", path, cfg.Sources)
	if allowSecret {
		if fc.Command != nil {
			cfg.Command = append([]string(nil), fc.Command...)
			cfg.Sources["command"] = path
		}
		merge(&cfg.CommandPromptMode, fc.CommandPromptMode, "command_prompt_mode", path, cfg.Sources)
		merge(&cfg.CommandOutput, fc.CommandOutput, "command_output", path, cfg.Sources)
		if fc.CommandEnv != nil {
			env := make(map[string]string, len(fc.CommandEnv))
			for key, value := range fc.CommandEnv {
				env[key] = value
			}
			cfg.CommandEnv = env
			cfg.Sources["command_env"] = path
		}
	}
	if fc.Scan != nil {
		s := fc.Scan
		merge(&cfg.Scan.Mode, s.Mode, "scan.mode", path, cfg.Sources)
		merge(&cfg.Scan.MinSeverity, s.MinSeverity, "scan.min_severity", path, cfg.Sources)
		mergeInt(&cfg.Scan.MaxFindings, s.MaxFindings, "scan.max_findings", path, cfg.Sources)
		mergeInt(&cfg.Scan.Concurrency, s.Concurrency, "scan.concurrency", path, cfg.Sources)
		if s.Exclude != nil {
			cfg.Scan.Exclude = append([]string(nil), s.Exclude...)
			cfg.Sources["scan.exclude"] = path
		}
		if s.Include != nil {
			cfg.Scan.Include = append([]string(nil), s.Include...)
			cfg.Sources["scan.include"] = path
		}
		if s.DisableRules != nil {
			cfg.Scan.DisableRules = append([]string(nil), s.DisableRules...)
			cfg.Sources["scan.disable_rules"] = path
		}
		if s.UseLLM != nil {
			v := *s.UseLLM
			cfg.Scan.UseLLM = &v
			cfg.Sources["scan.use_llm"] = path
		}
		if s.DeepReview != nil {
			cfg.Scan.DeepReview = *s.DeepReview
			cfg.Sources["scan.deep_review"] = path
		}
		if s.MaxFileBytes != nil {
			cfg.Scan.MaxFileBytes = *s.MaxFileBytes
			cfg.Sources["scan.max_file_bytes"] = path
		}
		if s.FollowLinks != nil {
			cfg.Scan.FollowLinks = *s.FollowLinks
			cfg.Sources["scan.follow_symlinks"] = path
		}
		if s.Baseline != nil {
			cfg.Scan.Baseline = *s.Baseline
			cfg.Sources["scan.baseline"] = path
		}
		if s.OSV != nil {
			cfg.Scan.OSV = *s.OSV
			cfg.Sources["scan.osv"] = path
		}
		if s.OSVBaseURL != nil {
			cfg.Scan.OSVBaseURL = strings.TrimSpace(*s.OSVBaseURL)
			cfg.Sources["scan.osv_base_url"] = path
		}
	}
	if fc.Output != nil {
		o := fc.Output
		merge(&cfg.Output.Format, o.Format, "output.format", path, cfg.Sources)
		merge(&cfg.Output.Path, o.Path, "output.path", path, cfg.Sources)
		merge(&cfg.Output.Color, o.Color, "output.color", path, cfg.Sources)
		if o.ShowFix != nil {
			cfg.Output.ShowFix = *o.ShowFix
			cfg.Sources["output.show_fix"] = path
		}
	}
	return nil
}

// validateProjectPath rejects absolute, traversal and .git paths in a project
// file. The value is only validated; callers keep the original spelling.
func validateProjectPath(key, value string) error {
	v := strings.TrimSpace(value)
	if v == "" || v == "-" {
		return nil
	}
	if _, err := safepath.CleanRel(v); err != nil {
		return fmt.Errorf("%s must be a relative path inside the project: %v", key, err)
	}
	return nil
}

func merge(dst *string, src *string, key, path string, sources map[string]string) {
	if src == nil {
		return
	}
	*dst = strings.TrimSpace(*src)
	sources[key] = path
}

func mergeInt(dst *int, src *int, key, path string, sources map[string]string) {
	if src == nil {
		return
	}
	*dst = *src
	sources[key] = path
}

func mergeFloat(dst *float64, src *float64, key, path string, sources map[string]string) {
	if src == nil {
		return
	}
	*dst = *src
	sources[key] = path
}

func applyEnv(cfg *Config) error {
	// Explicit Vigil variables win over provider conventions.
	setStr(&cfg.Provider, "VIGIL_PROVIDER", cfg.Sources)
	setStr(&cfg.Model, "VIGIL_MODEL", cfg.Sources)
	setStr(&cfg.BaseURL, "VIGIL_BASE_URL", cfg.Sources)
	setStr(&cfg.APIKey, "VIGIL_API_KEY", cfg.Sources)
	setInt(&cfg.MaxTokens, "VIGIL_MAX_TOKENS", cfg.Sources)
	setFloat(&cfg.Temperature, "VIGIL_TEMPERATURE", cfg.Sources)
	setInt(&cfg.MaxSteps, "VIGIL_MAX_STEPS", cfg.Sources)
	setDuration(&cfg.Timeout, "VIGIL_TIMEOUT", cfg.Sources)
	setStr(&cfg.CommandPromptMode, "VIGIL_COMMAND_PROMPT_MODE", cfg.Sources)
	setStr(&cfg.CommandOutput, "VIGIL_COMMAND_OUTPUT", cfg.Sources)
	setDuration(&cfg.CommandTimeout, "VIGIL_COMMAND_TIMEOUT", cfg.Sources)
	if raw := strings.TrimSpace(os.Getenv("VIGIL_COMMAND")); raw != "" {
		argv, err := parseCommandEnv(raw)
		if err != nil {
			return err
		}
		cfg.Command = argv
		cfg.Sources["command"] = "env:VIGIL_COMMAND"
	}
	setStr(&cfg.Scan.Mode, "VIGIL_MODE", cfg.Sources)
	setStr(&cfg.Scan.MinSeverity, "VIGIL_MIN_SEVERITY", cfg.Sources)
	setStr(&cfg.Scan.OSVBaseURL, "VIGIL_OSV_BASE_URL", cfg.Sources)
	if v := os.Getenv("VIGIL_OSV"); v != "" {
		cfg.Scan.OSV = parseBool(v)
		cfg.Sources["scan.osv"] = "env:VIGIL_OSV"
	}
	setInt(&cfg.Scan.MaxFindings, "VIGIL_MAX_FINDINGS", cfg.Sources)
	setInt(&cfg.Scan.Concurrency, "VIGIL_CONCURRENCY", cfg.Sources)
	setStr(&cfg.Output.Format, "VIGIL_FORMAT", cfg.Sources)
	if v := os.Getenv("VIGIL_USE_LLM"); v != "" {
		b := parseBool(v)
		cfg.Scan.UseLLM = &b
		cfg.Sources["scan.use_llm"] = "env:VIGIL_USE_LLM"
	}
	if v := os.Getenv("VIGIL_NO_LLM"); parseBool(v) {
		b := false
		cfg.Scan.UseLLM = &b
		cfg.Sources["scan.use_llm"] = "env:VIGIL_NO_LLM"
	}

	// If no explicit provider, infer from a well-known key.
	if cfg.Provider == "" {
		switch {
		case os.Getenv("ANTHROPIC_API_KEY") != "":
			cfg.Provider = ProviderAnthropic
			cfg.Sources["provider"] = "env:ANTHROPIC_API_KEY"
		case os.Getenv("OPENAI_API_KEY") != "":
			cfg.Provider = ProviderOpenAI
			cfg.Sources["provider"] = "env:OPENAI_API_KEY"
		case os.Getenv("GEMINI_API_KEY") != "" || os.Getenv("GOOGLE_API_KEY") != "":
			cfg.Provider = ProviderGemini
			if os.Getenv("GEMINI_API_KEY") != "" {
				cfg.Sources["provider"] = "env:GEMINI_API_KEY"
			} else {
				cfg.Sources["provider"] = "env:GOOGLE_API_KEY"
			}
		case os.Getenv("OPENROUTER_API_KEY") != "":
			cfg.Provider = ProviderOpenRouter
			cfg.Sources["provider"] = "env:OPENROUTER_API_KEY"
		case os.Getenv("DEEPSEEK_API_KEY") != "":
			cfg.Provider = ProviderDeepSeek
			cfg.Sources["provider"] = "env:DEEPSEEK_API_KEY"
		case os.Getenv("GROQ_API_KEY") != "":
			cfg.Provider = ProviderGroq
			cfg.Sources["provider"] = "env:GROQ_API_KEY"
		case os.Getenv("MISTRAL_API_KEY") != "":
			cfg.Provider = ProviderMistral
			cfg.Sources["provider"] = "env:MISTRAL_API_KEY"
		case os.Getenv("XAI_API_KEY") != "":
			cfg.Provider = ProviderXAI
			cfg.Sources["provider"] = "env:XAI_API_KEY"
		case os.Getenv("OPENCODE_API_KEY") != "":
			cfg.Provider = ProviderOpenCodeGo
			cfg.Sources["provider"] = "env:OPENCODE_API_KEY"
		case os.Getenv("OPENCODE_GO_API_KEY") != "":
			cfg.Provider = ProviderOpenCodeGo
			cfg.Sources["provider"] = "env:OPENCODE_GO_API_KEY"
		case os.Getenv("OLLAMA_HOST") != "":
			cfg.Provider = ProviderOllama
			cfg.Sources["provider"] = "env:OLLAMA_HOST"
		}
	}
	cfg.Provider = CanonicalProvider(cfg.Provider)
	if cfg.APIKey == "" {
		cfg.APIKey = providerKey(cfg.Provider)
		if cfg.APIKey != "" {
			cfg.Sources["api_key"] = "env:" + providerKeyName(cfg.Provider)
		}
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = providerBaseURL(cfg.Provider)
	}
	if cfg.Model == "" {
		cfg.Model = providerDefaultModel(cfg.Provider)
	}
	return nil
}

// parseCommandEnv accepts either a JSON array of argv strings (the portable
// form) or a single executable path with no arguments. A single path is never
// split on whitespace, so "C:\Program Files\..." keeps working.
func parseCommandEnv(raw string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if strings.HasPrefix(value, "[") {
		var argv []string
		if err := json.Unmarshal([]byte(value), &argv); err != nil {
			return nil, fmt.Errorf("VIGIL_COMMAND must be a JSON array of strings: %w", err)
		}
		return argv, nil
	}
	return []string{value}, nil
}

func providerKey(provider string) string {
	switch provider {
	case ProviderOpenAI:
		return os.Getenv("OPENAI_API_KEY")
	case ProviderAnthropic:
		return os.Getenv("ANTHROPIC_API_KEY")
	case ProviderGemini:
		if k := os.Getenv("GEMINI_API_KEY"); k != "" {
			return k
		}
		return os.Getenv("GOOGLE_API_KEY")
	case ProviderOpenRouter:
		return os.Getenv("OPENROUTER_API_KEY")
	case ProviderGroq:
		return os.Getenv("GROQ_API_KEY")
	case ProviderDeepSeek:
		return os.Getenv("DEEPSEEK_API_KEY")
	case ProviderMistral:
		return os.Getenv("MISTRAL_API_KEY")
	case ProviderXAI:
		return os.Getenv("XAI_API_KEY")
	case ProviderOpenCodeGo:
		if k := os.Getenv("OPENCODE_API_KEY"); k != "" {
			return k
		}
		return os.Getenv("OPENCODE_GO_API_KEY")
	default:
		return ""
	}
}

func providerKeyName(provider string) string {
	switch provider {
	case ProviderOpenAI:
		return "OPENAI_API_KEY"
	case ProviderAnthropic:
		return "ANTHROPIC_API_KEY"
	case ProviderGemini:
		if os.Getenv("GEMINI_API_KEY") != "" {
			return "GEMINI_API_KEY"
		}
		return "GOOGLE_API_KEY"
	case ProviderOpenRouter:
		return "OPENROUTER_API_KEY"
	case ProviderGroq:
		return "GROQ_API_KEY"
	case ProviderDeepSeek:
		return "DEEPSEEK_API_KEY"
	case ProviderMistral:
		return "MISTRAL_API_KEY"
	case ProviderXAI:
		return "XAI_API_KEY"
	case ProviderOpenCodeGo:
		if os.Getenv("OPENCODE_API_KEY") != "" {
			return "OPENCODE_API_KEY"
		}
		return "OPENCODE_GO_API_KEY"
	default:
		return ""
	}
}

// ProviderBaseURL returns the default endpoint for a provider.
func ProviderBaseURL(provider string) string { return providerBaseURL(provider) }

func providerBaseURL(provider string) string {
	switch provider {
	case ProviderOpenAI:
		return "https://api.openai.com/v1"
	case ProviderAnthropic:
		return "https://api.anthropic.com"
	case ProviderGemini:
		return "https://generativelanguage.googleapis.com/v1beta"
	case ProviderOpenRouter:
		return "https://openrouter.ai/api/v1"
	case ProviderGroq:
		return "https://api.groq.com/openai/v1"
	case ProviderDeepSeek:
		return "https://api.deepseek.com/v1"
	case ProviderMistral:
		return "https://api.mistral.ai/v1"
	case ProviderXAI:
		return "https://api.x.ai/v1"
	case ProviderOpenCodeGo:
		return "https://opencode.ai/inference/go/openai/v1"
	case ProviderOllama:
		if host := strings.TrimRight(os.Getenv("OLLAMA_HOST"), "/"); host != "" {
			if !strings.HasPrefix(host, "http") {
				host = "http://" + host
			}
			return host + "/v1"
		}
		return "http://localhost:11434/v1"
	case ProviderLMStudio:
		return "http://localhost:1234/v1"
	default:
		return ""
	}
}

func providerDefaultModel(provider string) string {
	switch provider {
	case ProviderOpenAI:
		return DefaultModel
	case ProviderAnthropic:
		return "claude-sonnet-4-5"
	case ProviderGemini:
		return "gemini-2.5-flash"
	case ProviderOpenRouter:
		return "anthropic/claude-sonnet-4.5"
	case ProviderGroq:
		return "llama-3.3-70b-versatile"
	case ProviderDeepSeek:
		return "deepseek-chat"
	case ProviderMistral:
		return "mistral-large-latest"
	case ProviderXAI:
		return "grok-4-fast"
	case ProviderOpenCodeGo:
		return "deepseek-v4.1-flash"
	case ProviderOllama:
		return "qwen2.5-coder:14b"
	case ProviderLMStudio:
		return "local-model"
	case ProviderCommand:
		return DefaultCommandModel
	default:
		return ""
	}
}

// Validate checks the resolved configuration.
// CanonicalProvider maps accepted aliases to the canonical provider name.
func CanonicalProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == ProviderOpenCode {
		return ProviderOpenCodeGo
	}
	return p
}

func (c *Config) Validate() error {
	c.Provider = CanonicalProvider(c.Provider)
	if c.Provider != "" {
		switch c.Provider {
		case ProviderOpenAI, ProviderAnthropic, ProviderGemini, ProviderOpenRouter,
			ProviderGroq, ProviderDeepSeek, ProviderMistral, ProviderXAI,
			ProviderOllama, ProviderLMStudio, ProviderCustom, ProviderOpenCodeGo,
			ProviderCommand:
		default:
			return fmt.Errorf("unknown provider %q (use one of: openai, anthropic, gemini, openrouter, groq, deepseek, mistral, xai, opencode-go, ollama, lmstudio, custom, command)", c.Provider)
		}
	}
	if c.Provider == ProviderCommand {
		if c.Model == "" {
			c.Model = DefaultCommandModel
		}
	} else if c.Provider != "" && c.Model == "" {
		return fmt.Errorf("provider %q requires a model", c.Provider)
	}
	// opencode-go is allowed without a key so the MCP server can start and
	// report "LLM disabled" until the user pastes the key; the LLM factory
	// still refuses to build a client without one. command uses the local
	// CLI's own authentication, so it needs no key either.
	if c.Provider != "" && c.Provider != ProviderOllama && c.Provider != ProviderLMStudio && c.Provider != ProviderOpenCodeGo && c.Provider != ProviderCommand && c.APIKey == "" {
		return fmt.Errorf("provider %q requires an API key (set VIGIL_API_KEY or the provider's key variable)", c.Provider)
	}
	if c.Provider == ProviderCustom && c.BaseURL == "" {
		return fmt.Errorf("provider custom requires base_url")
	}
	if c.Provider == ProviderCommand {
		if err := c.validateCommand(); err != nil {
			return err
		}
	}
	if c.MaxTokens < 1 {
		c.MaxTokens = 4096
	}
	if c.Temperature < 0 || c.Temperature > 2 {
		return fmt.Errorf("temperature must be between 0 and 2")
	}
	if c.MaxSteps < 1 {
		c.MaxSteps = 1
	}
	if c.Scan.Concurrency < 1 {
		c.Scan.Concurrency = 1
	}
	if c.Scan.Concurrency > 64 {
		c.Scan.Concurrency = 64
	}
	if c.Scan.Mode == "" {
		c.Scan.Mode = "standard"
	}
	switch c.Scan.Mode {
	case "quick", "standard", "deep":
	default:
		return fmt.Errorf("scan.mode must be quick, standard or deep (got %q)", c.Scan.Mode)
	}
	if c.Scan.MinSeverity == "" {
		c.Scan.MinSeverity = string(model.SeverityLow)
	}
	if _, ok := model.ParseSeverity(c.Scan.MinSeverity); !ok {
		return fmt.Errorf("scan.min_severity %q is not a severity", c.Scan.MinSeverity)
	}
	if c.Scan.MaxFindings < 0 {
		return fmt.Errorf("scan.max_findings cannot be negative")
	}
	switch c.Output.Format {
	case "", "md", "markdown", "json", "sarif", "html":
	default:
		return fmt.Errorf("output.format must be md, json, sarif or html (got %q)", c.Output.Format)
	}
	switch c.Output.Color {
	case "", "auto", "always", "never":
	default:
		return fmt.Errorf("output.color must be auto, always or never")
	}
	if c.Timeout <= 0 {
		c.Timeout = 120 * time.Second
	}
	return nil
}

// validateCommand checks the local CLI provider. The executable is required;
// prompt and output modes are small closed sets so a typo fails at startup
// instead of silently feeding the prompt on stdin or misparsing the output.
func (c *Config) validateCommand() error {
	if len(c.Command) == 0 || strings.TrimSpace(c.Command[0]) == "" {
		return fmt.Errorf("provider %q requires command (set command in the user config or VIGIL_COMMAND)", c.Provider)
	}
	for _, arg := range c.Command {
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("command arguments must not contain NUL bytes")
		}
	}

	if c.CommandPromptMode == "" {
		c.CommandPromptMode = CommandPromptArg
	}
	switch c.CommandPromptMode {
	case CommandPromptArg, CommandPromptStdin:
	default:
		return fmt.Errorf("command_prompt_mode must be arg or stdin (got %q)", c.CommandPromptMode)
	}

	if c.CommandOutput == "" {
		c.CommandOutput = CommandOutputAuto
	}
	switch c.CommandOutput {
	case CommandOutputAuto, CommandOutputText, CommandOutputOpenCodeJSON:
	default:
		return fmt.Errorf("command_output must be auto, text or opencode-json (got %q)", c.CommandOutput)
	}

	if c.CommandTimeout < 0 {
		return fmt.Errorf("command_timeout cannot be negative")
	}
	if c.CommandMaxOutputBytes < 0 {
		return fmt.Errorf("command_max_output_bytes cannot be negative")
	}
	if c.CommandMaxOutputBytes == 0 {
		c.CommandMaxOutputBytes = DefaultCommandMaxOutputBytes
	}
	if c.CommandMaxOutputBytes > MaxCommandMaxOutputBytes {
		c.CommandMaxOutputBytes = MaxCommandMaxOutputBytes
	}

	for key := range c.CommandEnv {
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "=\x00") {
			return fmt.Errorf("command_env keys must be non-empty and must not contain '=' or NUL")
		}
	}
	return nil
}

// LLMEnabled reports whether the scan should call a model.
func (c *Config) LLMEnabled() bool {
	if c.Scan.UseLLM != nil {
		return *c.Scan.UseLLM && c.Provider != ""
	}
	return c.Provider != ""
}

// Redacted returns a copy safe to print or serialise.
func (c Config) Redacted() Config {
	if c.APIKey != "" {
		c.APIKey = "***"
	}
	c.BaseURL = RedactURL(c.BaseURL)
	if len(c.CommandEnv) > 0 {
		env := make(map[string]string, len(c.CommandEnv))
		for key := range c.CommandEnv {
			env[key] = "***"
		}
		c.CommandEnv = env
	}
	return c
}

// RedactURL removes userinfo and key-like query parameters from a base URL so
// it can be printed in status output and stored in scan results.
func RedactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	q := u.Query()
	changed := false
	for k := range q {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "key") || strings.Contains(lk, "token") ||
			strings.Contains(lk, "secret") || strings.Contains(lk, "auth") {
			q.Set(k, "REDACTED")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func setStr(dst *string, env string, sources map[string]string) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		*dst = v
		sources[strings.ToLower(strings.TrimPrefix(env, "VIGIL_"))] = "env:" + env
	}
}

func setInt(dst *int, env string, sources map[string]string) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
			sources[strings.ToLower(strings.TrimPrefix(env, "VIGIL_"))] = "env:" + env
		}
	}
}

func setFloat(dst *float64, env string, sources map[string]string) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			*dst = f
			sources[strings.ToLower(strings.TrimPrefix(env, "VIGIL_"))] = "env:" + env
		}
	}
}

func setDuration(dst *time.Duration, env string, sources map[string]string) {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*dst = d
			sources[strings.ToLower(strings.TrimPrefix(env, "VIGIL_"))] = "env:" + env
		}
	}
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
