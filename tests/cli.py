#!/usr/bin/env python3
"""Configuration and process-control checks that do not need TCP sockets."""

import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve())


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vergeauth-cli-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / ".vergeauth"
        self.env = os.environ.copy()
        self.env["HOME"] = self.temp.name

    def run_cli(self, *args, success=False, env=None):
        result = subprocess.run([BINARY, *args], env=env or self.env, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr.decode())
        self.assertNotIn(b"runtime error:", result.stderr)
        self.assertNotIn(b"ERROR: AddressSanitizer", result.stderr)
        return result

    def test_help_and_invalid_arguments(self):
        self.assertIn(b"Usage:", self.run_cli("-h", success=True).stdout)
        self.assertIn(b"1.0.0", self.run_cli("-v", success=True).stdout)
        self.run_cli("-d", "-r")
        self.run_cli("extra")
        self.run_cli("-f")
        self.run_cli("-z")

    def test_configuration_errors_and_default_path(self):
        self.run_cli()
        for content in (
            b"", b"listen 0\nupstream localhost:7897\n", b"listen 65536\nupstream localhost:7897\n",
            b"listen 12\nupstream localhost\n", b"listen 12\nupstream [bad]:12\n",
            b"listen 12\nlisten 13\nupstream localhost:12\n",
            b"listen 12\nupstream localhost:12\nuser a b\nuser a c\n",
            b"listen 12\nupstream localhost:12\nuser '' b\n",
            b"listen 12\nupstream localhost:12\nuser 'a:b' c\n",
            b"listen 12\nupstream localhost:12\nuser a 'unterminated\n",
            b"listen 12\nupstream localhost:12\nuser a b\x00hidden\n",
            b"listen 12\nupstream localhost:12\nunknown a\n",
            b"x" * 8192,
        ):
            self.path.write_bytes(content)
            self.run_cli()
            self.run_cli("-f", str(self.path))
        env = self.env.copy()
        env.pop("HOME")
        self.assertIn(b"HOME", self.run_cli(env=env).stderr)

    def test_stale_pid_is_not_signalled(self):
        self.path.write_text("listen 7898\nupstream localhost:7897\nuser a b\n")
        pid_path = Path(str(self.path) + ".pid")
        pid_path.write_text(f"{os.getpid()}\n")
        self.assertIn(b"no running instance", self.run_cli("-r").stderr)
        pid_path.unlink()
        pid_path.symlink_to(self.path)
        self.run_cli("-r")

    def test_reload_uses_lock_owner_and_duplicate_daemon_fails(self):
        self.path.write_text("listen 7898\nupstream localhost:7897\nuser a b\n")
        received = []
        original = signal.signal(signal.SIGHUP, lambda signum, frame: received.append(signum))
        self.addCleanup(signal.signal, signal.SIGHUP, original)
        with open(str(self.path) + ".pid", "w+") as pidfile:
            pidfile.write("999999\n")  # The text is deliberately unrelated to the lock owner.
            pidfile.flush()
            fcntl.lockf(pidfile, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0)
            self.run_cli("-r", success=True)
            self.assertEqual(received, [signal.SIGHUP])
            self.run_cli()
            self.run_cli("-d")  # Parent waits for the child's startup failure.
            pidfile.seek(0)
            self.assertEqual(pidfile.read(), "999999\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
