"""Tests for the Python launcher that delegates to the npm Vigil CLI."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PYTHON_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = PYTHON_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lv24_vigil import __version__
from lv24_vigil.cli import NPM_PACKAGE, NPM_VERSION_ENV, main

_FAKE_NPX = '''\
import json
import os
import sys

record = {
    "argv": sys.argv[1:],
    "env": {
        key: value
        for key, value in os.environ.items()
        if key.startswith("VIGIL_") or key == "PATH"
    },
}
with open(os.environ["VIGIL_TEST_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\\n")
raise SystemExit(3)
'''


class MainTests(unittest.TestCase):
    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.root = Path(self._tempdir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.empty_dir = self.root / "empty"
        self.empty_dir.mkdir()
        self.log_path = self.root / "calls.jsonl"

        self._saved_env = {
            key: os.environ.get(key)
            for key in ("VIGIL_NPM_VERSION", "VIGIL_TEST_LOG")
        }
        self.addCleanup(self._restore_env)
        os.environ.pop("VIGIL_NPM_VERSION", None)
        os.environ["VIGIL_TEST_LOG"] = str(self.log_path)

        self._write_fake_npx()

    def _restore_env(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _write_fake_npx(self):
        script = self.bin_dir / "fake_npx.py"
        script.write_text(_FAKE_NPX, encoding="utf-8")

        if os.name == "nt":
            launcher = self.bin_dir / "npx.cmd"
            content = '@echo off\r\n"{0}" "%~dp0fake_npx.py" %*\r\n'.format(
                sys.executable
            )
            with launcher.open("w", encoding="utf-8", newline="") as handle:
                handle.write(content)
        else:
            launcher = self.bin_dir / "npx"
            content = '#!/bin/sh\nexec "{0}" "$(dirname "$0")/fake_npx.py" "$@"\n'.format(
                sys.executable
            )
            launcher.write_text(content, encoding="utf-8")
            launcher.chmod(
                launcher.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )

    def _invoke(self, args, *, env=None, path=None, cwd=None):
        call_env = {
            "PATH": str(self.bin_dir if path is None else path),
            "VIGIL_TEST_LOG": str(self.log_path),
        }
        if os.name == "nt":
            call_env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
        if env:
            call_env.update(env)

        stderr = io.StringIO()
        previous_cwd = os.getcwd()
        if cwd is not None:
            os.chdir(cwd)
        try:
            with mock.patch.dict(os.environ, call_env, clear=False):
                with contextlib.redirect_stderr(stderr):
                    code = main(list(args))
        finally:
            if cwd is not None:
                os.chdir(previous_cwd)
        return code, stderr.getvalue()

    def _calls(self):
        if not self.log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def test_forwards_arguments_and_returns_child_exit_code(self):
        code, stderr = self._invoke(["scan", "--no-llm", "."])

        self.assertEqual(code, 3)
        self.assertEqual(stderr, "")
        calls = self._calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0]["argv"],
            [
                "--yes",
                "{0}@{1}".format(NPM_PACKAGE, __version__),
                "scan",
                "--no-llm",
                ".",
            ],
        )

    def test_version_matches_pyproject(self):
        pyproject = PYTHON_DIR / "pyproject.toml"
        match = re.search(
            r'^version\s*=\s*"([^"]+)"',
            pyproject.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), __version__)

    def test_uses_env_override_and_inherits_it(self):
        code, stderr = self._invoke(
            ["--help"], env={NPM_VERSION_ENV: "latest"}
        )

        self.assertEqual(code, 3)
        self.assertEqual(stderr, "")
        call = self._calls()[0]
        self.assertEqual(
            call["argv"],
            ["--yes", "{0}@latest".format(NPM_PACKAGE), "--help"],
        )
        self.assertEqual(call["env"][NPM_VERSION_ENV], "latest")

    def test_missing_npx_returns_127_with_install_hint(self):
        code, stderr = self._invoke(
            [], path=self.empty_dir, cwd=self.empty_dir
        )

        self.assertEqual(code, 127)
        self.assertIn("npx", stderr)
        self.assertIn("Node.js", stderr)
        self.assertIn("npm", stderr)
        self.assertIn("lv24-vigil", stderr)
        self.assertEqual(self._calls(), [])

    def test_keyboard_interrupt_returns_130(self):
        with mock.patch(
            "lv24_vigil.cli.subprocess.run",
            side_effect=KeyboardInterrupt,
        ):
            code, stderr = self._invoke([])

        self.assertEqual(code, 130)
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
