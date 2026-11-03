#!/usr/bin/env python3
"""Real filesystem installation checks; fixture scripts are not Rust evidence."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "prepare_operator_native", Path(__file__).resolve().parents[1] / "prepare_operator_native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeInstallation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="operator native ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.target = self.root / "target with spaces λ"
        self.target.mkdir()
        self.source = self.target / "debug/fg"
        self.source.parent.mkdir()
        self.bytes = b"#!/bin/sh\nprintf 'trusted fixture\\n'\n"
        self.source.write_bytes(self.bytes)
        self.source.chmod(0o775)

    def prepare(self, source=None, target=None):
        with redirect_stderr(io.StringIO()) as diagnostics:
            result = native.prepare(source or self.source, target or self.target)
        return result, diagnostics.getvalue()

    def test_same_bytes_are_private_read_only_executable_and_delivery_is_unchanged(self):
        first, message = self.prepare()
        second, _ = self.prepare()
        self.assertNotEqual(first, second)
        for installed in (first, second):
            self.assertEqual(installed.read_bytes(), self.bytes)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o500)
            self.assertEqual(installed.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(installed.parent.parent, self.target)
        self.assertEqual(self.source.read_bytes(), self.bytes)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o775)
        self.assertIn(hashlib.sha256(self.bytes).hexdigest(), message)

    def test_caller_target_alias_resolves_to_a_canonical_operator_path(self):
        alias = self.root / "alias"
        alias.symlink_to(self.target, target_is_directory=True)
        installed, _ = self.prepare(alias / "debug/fg", alias)
        self.assertEqual(installed, installed.resolve())

    def test_source_symlinks_and_parent_escape_are_refused(self):
        alias = self.target / "alias-fg"
        alias.symlink_to(self.source)
        with self.assertRaises(ValueError):
            self.prepare(alias)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "fg").write_bytes(self.bytes)
        (outside / "fg").chmod(0o700)
        (self.target / "escaped").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.prepare(self.target / "escaped/fg")

    def test_non_executable_empty_directory_and_fifo_are_refused_before_copy(self):
        self.source.chmod(0o600)
        with self.assertRaises(ValueError):
            self.prepare()
        self.source.chmod(0o700)
        self.source.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.prepare()
        with self.assertRaises(ValueError):
            self.prepare(self.source.parent)
        fifo = self.target / "fifo"
        os.mkfifo(fifo, 0o700)
        with self.assertRaises(ValueError):
            self.prepare(fifo)
        self.assertFalse(list(self.target.glob(".operator-native-*")))

    def test_resource_limit_has_an_exact_permitted_twin(self):
        with patch.object(native, "MAX_EXECUTABLE_BYTES", len(self.bytes)):
            self.prepare()
        with patch.object(native, "MAX_EXECUTABLE_BYTES", len(self.bytes) - 1):
            with self.assertRaises(ValueError):
                self.prepare()

    def test_changed_real_source_during_flush_never_publishes_an_executable(self):
        sync = os.fsync
        changed = False

        def mutate(descriptor):
            nonlocal changed
            if not changed:
                changed = True
                self.source.write_bytes(self.bytes + b"changed")
            return sync(descriptor)

        with patch.object(native.os, "fsync", mutate):
            with self.assertRaisesRegex(ValueError, "changed"):
                self.prepare()
        installed = list(self.target.glob(".operator-native-*/fg"))
        self.assertEqual(len(installed), 1)
        self.assertEqual(installed[0].stat().st_mode & 0o777, 0o600)

    def test_copy_sync_failure_keeps_partial_output_non_executable(self):
        with patch.object(native.os, "fsync", side_effect=OSError("injected disk failure")):
            with self.assertRaises(OSError):
                self.prepare()
        self.assertEqual(next(self.target.glob(".operator-native-*/fg")).stat().st_mode & 0o777, 0o600)

    def test_late_sync_failure_retains_complete_but_unselected_snapshot(self):
        sync = os.fsync
        calls = 0

        def fail_after_mode(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected mode durability failure")
            return sync(descriptor)

        with patch.object(native.os, "fsync", fail_after_mode):
            with self.assertRaises(OSError):
                self.prepare()
        installed = next(self.target.glob(".operator-native-*/fg"))
        self.assertEqual(installed.read_bytes(), self.bytes)
        self.assertEqual(installed.stat().st_mode & 0o777, 0o500)

    def test_relative_and_control_paths_are_refused(self):
        for source, target in (("relative", self.target), (self.source, "relative"),
                               (str(self.source) + "\n", self.target)):
            with self.assertRaises(ValueError):
                self.prepare(source, target)


if __name__ == "__main__":
    unittest.main()
