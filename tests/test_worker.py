import contextlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / 'src-tauri/src'
spec = importlib.util.spec_from_file_location('worker', ROOT / 'worker.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='burniso-worker-test-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.block = patch.object(w, 'BLOCK', 64)
        self.block.start()
        self.addCleanup(self.block.stop)

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return str(path)

    def test_short_reads_are_accumulated_and_eof_rejected(self):
        parts = iter([b'ab', b'c', b'd'])
        self.assertEqual(w.read_exact(lambda n: next(parts), 4), b'abcd')
        with self.assertRaises(OSError): w.read_exact(lambda n: b'', 1)

    def test_partial_writes_are_completed(self):
        received = bytearray()
        def short_write(fd, data):
            received.extend(data[:2])
            return min(2, len(data))
        with patch.object(w.os, 'write', short_write): w.write_all(0, b'abcdefg')
        self.assertEqual(received, b'abcdefg')

    def test_full_backup_preserves_tail_and_publishes_atomically(self):
        data = bytes(range(251))
        cfg = dict(device=self.file('source', data), destination=str(self.root / 'full.img'), size=len(data))
        w.backup(cfg)
        self.assertEqual(Path(cfg['destination']).read_bytes(), data)
        self.assertFalse(Path(cfg['destination'] + '.partial').exists())
        with self.assertRaises(FileExistsError): w.backup(cfg)

    def test_truncated_backup_is_never_published(self):
        cfg = dict(device=self.file('source', b'x' * 65), destination=str(self.root / 'short.img'), size=130)
        with self.assertRaises(OSError): w.backup(cfg)
        self.assertFalse(Path(cfg['destination']).exists())
        self.assertTrue(Path(cfg['destination'] + '.partial').exists())

    def test_existing_partial_is_not_overwritten(self):
        path = self.file('out.partial', b'keep')
        with self.assertRaises(FileExistsError):
            w.backup(dict(device=self.file('source', b'a'), destination=path[:-8], size=1))
        self.assertEqual(Path(path).read_bytes(), b'keep')

    def test_full_diagnostic_checks_tail(self):
        path = self.file('disk', bytes(133))
        w.diagnostic(dict(mode='full', device=path, size=133))
        self.assertEqual(Path(path).read_bytes(), b'\xff' * 133)

    def test_corruption_outside_first_byte_is_detected(self):
        path = self.file('disk', bytes(133))
        original = w.os.fsync
        def corrupt(fd):
            original(fd)
            with open(path, 'r+b', buffering=0) as file:
                file.seek(131)
                file.write(b'\x7f')
        with patch.object(w.os, 'fsync', corrupt), self.assertRaisesRegex(OSError, 'Byte 131'):
            w.diagnostic(dict(mode='full', device=path, size=133))

    def test_surface_short_read_fails(self):
        with self.assertRaises(OSError):
            w.diagnostic(dict(mode='surface', device=self.file('disk', bytes(65)), size=133))

    def test_verified_burn_uses_source_once(self):
        data = bytes(range(251))
        cfg = dict(device=self.file('disk', bytes(300)), source=self.file('image', data), size=len(data), verify=True)
        w.burn(cfg)
        self.assertEqual(Path(cfg['device']).read_bytes(), data + bytes(49))

    def test_verification_detects_changed_disk(self):
        cfg = dict(device=self.file('disk', bytes(133)), source=self.file('image', b'a' * 133), size=133, verify=True)
        original = w.os.fsync
        def corrupt(fd):
            original(fd)
            with open(cfg['device'], 'r+b', buffering=0) as file:
                file.seek(131)
                file.write(b'z')
        with patch.object(w.os, 'fsync', corrupt), self.assertRaisesRegex(OSError, 'Verifizierung'):
            w.burn(cfg)

    def test_xz_decompresses_only_once(self):
        xz = shutil.which('xz')
        if not xz: self.skipTest('xz missing')
        cfg = dict(device=self.file('disk', bytes(251)), source=self.file('image.xz', lzma.compress(bytes(range(251)))), size=251, verify=True, xz=xz)
        with patch.object(w.subprocess, 'Popen', wraps=subprocess.Popen) as popen:
            w.burn(cfg)
            self.assertEqual(popen.call_count, 1)
        self.assertEqual(Path(cfg['device']).read_bytes(), bytes(range(251)))

    def test_speed_never_exceeds_small_device(self):
        path = self.file('disk', bytes(133))
        w.speed(dict(device=path, size=133))
        self.assertEqual(Path(path).stat().st_size, 133)

    def test_supervisor_cancels_without_stdout_activity(self):
        fifo = self.root / 'blocked-source'
        os.mkfifo(fifo)
        cfg = dict(mode='backup', device=str(fifo), destination=str(self.root / 'out'), size=64)
        script = (ROOT / 'worker.py').read_text() + '\n' + (ROOT / 'supervisor.py').read_text()
        child = subprocess.Popen([sys.executable, '-u', '-c', script, json.dumps(cfg)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(.2)
            out, err = child.communicate(b'CANCEL\n', timeout=5)
            self.assertEqual(child.returncode, 130, (out, err))
            self.assertNotIn(b'DONE', out)
            self.assertFalse((self.root / 'out').exists())
        finally:
            if child.poll() is None: child.kill(); child.wait()

if __name__ == '__main__': unittest.main()
