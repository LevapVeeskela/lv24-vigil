package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

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
	positional, err := parseFlagSet(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, "Usage: vigil mcp [--root DIR]\n\nRuns Vigil as an MCP server over stdio. stdout is the protocol stream.\n")
		return nil
	}
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	if len(positional) > 0 {
		return fmt.Errorf("mcp takes no positional arguments (got %q); use --root DIR", positional[0])
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	a, err := app.New(*root, logger)
	if err != nil {
		return err
	}
	defer a.Close()
	printWarnings(stderr, a.Warnings)

	srv := mcp.NewServer("vigil", version.Version, "Vigil security auditor")
	srv.Logger = logger
	srv.Instructions = "Vigil audits the configured project for security issues. Tools are prefixed vigil_; write paths are confined to the server root."
	tools.Register(srv, tools.Deps{App: a, Version: version.Version})

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
