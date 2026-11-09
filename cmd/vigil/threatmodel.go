package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

func runThreatModel(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("threat-model")
	output := fs.String("output", "", "write the Markdown threat model to a file")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, "Usage: vigil threat-model [path] [--output FILE]\n\nGenerates a Markdown threat model for the project with the configured model.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("threat-model: %w", err)
	}
	if len(positional) > 1 {
		return fmt.Errorf("expected at most one path, got %d", len(positional))
	}
	root := "."
	if len(positional) == 1 {
		root = positional[0]
	}

	a, err := buildApp(root, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	printWarnings(stderr, a.Warnings)

	ctx, stop := signalContext()
	defer stop()

	document, err := a.ThreatModel(ctx)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(document, "\n") {
		document += "\n"
	}

	if strings.TrimSpace(*output) == "" || *output == "-" {
		if _, err := io.WriteString(stdout, document); err != nil {
			return fmt.Errorf("write threat model: %w", err)
		}
		return nil
	}
	if err := writeFile(*output, []byte(document)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", *output)
	return nil
}
