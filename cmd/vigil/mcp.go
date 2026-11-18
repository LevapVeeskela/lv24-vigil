package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/levapveeskela/lv24-vigil/internal/app"
	"github.com/levapveeskela/lv24-vigil/internal/mcp"
	"github.com/levapveeskela/lv24-vigil/internal/tools"
	"github.com/levapveeskela/lv24-vigil/internal/version"
)

// runMCP serves the Model Context Protocol over stdio. stdout carries JSON-RPC
// only; every diagnostic goes to stderr.
func runMCP(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("mcp")
	root := fs.String("root", ".", "project root exposed to MCP tools")
	readOnly := fs.Bool("read-only", envBool("VIGIL_MCP_READ_ONLY"), "hide vigil_fix and reject all writes")
	offline := fs.Bool("offline", envBool("VIGIL_MCP_OFFLINE"), "disable model and OSV network access")
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, `Usage: vigil mcp [--root DIR] [--read-only] [--offline]

Runs Vigil as an MCP server over stdio. stdout is the protocol stream.

  --read-only   Hide vigil_fix and reject baseline, source and report writes.
  --offline     Disable every network call: no model, no OSV lookups.

The same modes can be set with VIGIL_MCP_READ_ONLY=1 and VIGIL_MCP_OFFLINE=1.
Scan history is still written locally in read-only mode so later tools can
address the findings.
`)
		return nil
	}
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("mcp takes no positional arguments (got %q); use --root DIR", positional[0])
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	var opts []app.Option
	if *offline {
		opts = append(opts, app.WithOffline())
	}
	a, err := app.New(*root, logger, opts...)
	if err != nil {
		return err
	}
	defer a.Close()
	printWarnings(stderr, a.Warnings)

	srv := mcp.NewServer("vigil", version.Version, "Vigil security auditor")
	srv.Logger = logger
	srv.Instructions = "Vigil audits the configured project for security issues. Tools are prefixed vigil_; write paths are confined to the server root."
	if *readOnly {
		srv.Instructions += " Read-only mode is on: vigil_fix is hidden, and baseline, source and report writes are rejected."
	}
	if *offline {
		srv.Instructions += " Offline mode is on: no model or OSV network calls are made."
	}
	tools.Register(srv, tools.Deps{
		App:      a,
		Version:  version.Version,
		ReadOnly: *readOnly,
		Offline:  *offline,
	})
	if *readOnly {
		srv.HideTools("vigil_fix")
	}

	ctx, stop := signalContext()
	defer stop()

	// Serve blocks on stdin. Run it in a goroutine so SIGINT/SIGTERM can end the
	// process cleanly even while no request is arriving.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ServeStdio(ctx, stdinReader, stdout)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	case <-ctx.Done():
		return nil
	}
}

// envBool reads a boolean switch from the environment. Unset or unparsable
// values leave the flag at its default: a typo must not silently disable a
// safety mode, and it must not silently enable one either.
func envBool(name string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(name)))
	return err == nil && v
}
