package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/config"
	"github.com/levapveeskela/lv24-vigil/internal/sbom"
)

// runSBOM builds a software bill of materials from the dependency manifests
// Vigil already understands and renders it as CycloneDX 1.6 or SPDX 2.3 JSON.
// Building is offline: it reads manifests and never queries an advisory service.
//
// Excludes come from two places: the project's explicit .vigil.yaml
// scan.exclude list and repeatable --exclude flags. The built-in scanner
// defaults are not applied, because they filter source content (*.png, *.lock,
// package-lock.json) and would hide the dependency manifests an SBOM is made of.
// For the same reason only the directory-oriented patterns of an explicit
// scan.exclude list are applied; a project that excludes go.sum or
// package-lock.json from text scanning still needs those lockfiles inventoried.
func runSBOM(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("sbom")
	flagPath := fs.String("path", "", "directory to inventory (default .); a positional path also works")
	format := fs.String("format", "cyclonedx", "output format: cyclonedx or spdx")
	includeDev := fs.Bool("include-dev", false, "include development dependencies")
	output := fs.String("output", "", "write the document to FILE (\"-\" for stdout)")
	var exclude stringList
	fs.Var(&exclude, "exclude", "skip matching manifests (repeatable, comma-separated)")

	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, `Usage: vigil sbom [path] [flags]

Builds a software bill of materials from supported manifests and lockfiles and
prints CycloneDX 1.6 or SPDX 2.3 JSON. Offline: no package manager runs, no
advisory service is queried and no source file is written.

The project's .vigil.yaml scan.exclude list is directory-oriented: patterns that
prune a directory tree (ideas/**, internal/rules/**, **/testdata/**,
node_modules/**) are applied, and file patterns such as go.sum, *.lock or
package-lock.json are ignored so the inventory keeps every manifest. --exclude
adds patterns verbatim and may name files. Coverage warnings, including a
truncated inventory, go to stderr and are recorded in the document.

Flags:
  --path DIR              directory to inventory (default .); a positional path also works
  --format cyclonedx|spdx output format (default cyclonedx)
  --include-dev           include development dependencies (default false)
  --exclude GLOB          skip matching manifests (repeatable, comma-separated)
  --output FILE           write the document to FILE ("-" = stdout)
`)
		return nil
	}
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}

	root, err := resolvePathArgument("sbom", positional, *flagPath)
	if err != nil {
		return err
	}
	formatName, err := parseSBOMFormat(*format)
	if err != nil {
		return err
	}

	cfg, err := config.Load(root)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}
	excludes := sbomExcludes(cfg, exclude)

	ctx, stop := signalContext()
	defer stop()

	doc, err := sbom.Build(ctx, root, *includeDev, sbom.WithExcludes(excludes))
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}
	data, err := doc.Render(formatName)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}
	for _, warning := range doc.Warnings {
		fmt.Fprintf(stderr, "sbom: warning: %s\n", warning)
	}
	if *output == "" || *output == "-" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("sbom: write document: %w", err)
		}
		return nil
	}
	if err := writeFile(*output, data); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s (%d components", *output, len(doc.Packages))
	if len(doc.Warnings) > 0 {
		fmt.Fprintf(stdout, ", %d warnings", len(doc.Warnings))
	}
	fmt.Fprintln(stdout, ")")
	return nil
}

// sbomExcludes merges the project's explicitly configured scan.exclude list with
// the CLI patterns. config.Load falls back to the built-in scanner defaults when
// no file sets scan.exclude; Sources records that provenance, so an unset list
// stays empty here. The defaults exist to skip non-source files while scanning
// text, and applying them would drop dependency manifests (*.lock,
// package-lock.json, go.sum) from the inventory.
//
// An explicit scan.exclude list is a scanner content filter too, so only its
// directory-oriented patterns are carried over: a project that excludes go.sum,
// package-lock.json or *.lock from text scanning still wants those lockfiles in
// its SBOM. Patterns naming files are ignored unless --exclude repeats them,
// because --exclude is the caller's explicit inventory choice and is applied
// verbatim.
func sbomExcludes(cfg config.Config, explicit stringList) []string {
	var patterns []string
	if cfg.Sources["scan.exclude"] != "" {
		for _, pattern := range cfg.Scan.Exclude {
			if isDirectoryExclude(pattern) {
				patterns = append(patterns, pattern)
			}
		}
	}
	patterns = append(patterns, explicit...)
	return patterns
}

// isDirectoryExclude reports whether a scan.exclude pattern prunes directories
// rather than individual files. "**" or a trailing "/" makes a pattern
// directory-oriented (ideas/**, **/testdata/**, node_modules/**, vendor/);
// everything else may name a manifest or lockfile and is not an SBOM exclude.
func isDirectoryExclude(pattern string) bool {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return false
	}
	return strings.Contains(trimmed, "/**") || strings.HasSuffix(trimmed, "/")
}

// parseSBOMFormat accepts the short CLI names and the canonical format names
// the sbom package uses.
func parseSBOMFormat(v string) (sbom.Format, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "cyclonedx", "cyclonedx+json", "cyclonedx-json":
		return sbom.FormatCycloneDXJSON, nil
	case "spdx", "spdx+json", "spdx-json":
		return sbom.FormatSPDXJSON, nil
	default:
		return "", fmt.Errorf("sbom: --format must be cyclonedx or spdx (got %q)", v)
	}
}
