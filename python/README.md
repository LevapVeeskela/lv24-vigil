# lv24-vigil (Python launcher)

A thin Python launcher for **Vigil**, a local-first security auditor for code.
Vigil itself is a Go binary distributed as a Node.js command-line tool published
on npm as [`lv24-vigil`](https://www.npmjs.com/package/lv24-vigil). This package
does not reimplement Vigil and does not bundle Node.js: the `vigil` command
delegates to the npm package through `npx`.

The npm package remains the canonical distribution. The PyPI package only
contains this launcher.

## Prerequisites

- **Node.js 18 or newer**, including npm and npx
  ([nodejs.org](https://nodejs.org/)).
- Network access on first run, or an npm cache that already contains the
  requested package, because `npx` may download it.
- Python 3.9 or newer.

## Installation

```bash
pip install lv24-vigil
```

This installs two equivalent console scripts:

- `vigil`
- `lv24-vigil`

## Usage

```bash
vigil version
vigil scan --no-llm
vigil status
```

All arguments are forwarded unchanged to the npm CLI. The child process
inherits the terminal, environment and working directory, and its exit code is
propagated. You can also run:

```bash
python -m lv24_vigil --help
```

If `npx` cannot be found, the launcher exits with code `127` and prints an
installation hint. An interrupted run exits with code `130`.

## Version pinning

By default the launcher runs the npm package version matching its own version
(currently `0.8.0`). Override it with `VIGIL_NPM_VERSION` to use any npm version
or tag:

```bash
VIGIL_NPM_VERSION=latest vigil --help
VIGIL_NPM_VERSION=0.8.0 vigil scan --no-llm
```

PowerShell:

```powershell
$env:VIGIL_NPM_VERSION = "latest"; vigil --help
```

## Links

- Main repository and documentation:
  <https://github.com/LevapVeeskela/lv24-vigil>
- Installation options:
  <https://github.com/LevapVeeskela/lv24-vigil/blob/main/docs/install.md>
- PyPI publishing and Trusted Publishing:
  <https://github.com/LevapVeeskela/lv24-vigil/blob/main/docs/pypi.md>
- Issues:
  <https://github.com/LevapVeeskela/lv24-vigil/issues>
- npm package:
  <https://www.npmjs.com/package/lv24-vigil>

## License

Apache-2.0, same as the Vigil repository and the canonical npm package.
