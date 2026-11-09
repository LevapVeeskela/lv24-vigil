package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/levapveeskela/lv24-vigil/internal/report"
)

func runReport(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("report")
	format := fs.String("format", "", "report format: md, json, sarif or html")
	output := fs.String("output", "", "write the report to a file (\"-\" for stdout)")
	scanID := fs.String("scan", "", "scan ID to render (default: last scan)")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, "Usage: vigil report [--format FMT] [--output FILE] [--scan ID]\n\nRenders a stored scan. Without --scan the most recent scan is used.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("report takes no arguments (got %q); use --scan ID", positional[0])
	}

	a, err := buildApp(".", stderr)
	if err != nil {
		return err
	}
	defer a.Close()

	res, err := loadScan(a, *scanID)
	if err != nil {
		return err
	}
	canonical, err := canonicalFormat(firstNonEmpty(*format, a.Config.Output.Format))
	if err != nil {
		return err
	}

	data, err := report.Render(canonical, res, report.Options{ShowFix: a.Config.Output.ShowFix})
	if err != nil {
		return err
	}
	path := firstNonEmpty(*output, a.Config.Output.Path)
	if path == "" || path == "-" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		return nil
	}
	if err := writeFile(path, data); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\n", path)
	return nil
}
