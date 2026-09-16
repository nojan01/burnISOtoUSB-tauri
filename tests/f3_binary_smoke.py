"""Bounded smoke test using the real bundled F3 programs, never attached disks.

Writes at most one 1-GiB test file to a private temporary folder, verifies it,
corrupts one byte, and requires F3 to detect the corruption despite exit code 0.
"""
import importlib.util
import os
from pathlib import Path
import platform
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('f3', ROOT / 'src-tauri/src/f3_worker.py')
f3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f3)
arch = 'aarch64' if platform.machine() == 'arm64' else 'x86_64'
binaries = ROOT / 'src-tauri/binaries'
with tempfile.TemporaryDirectory(prefix='burniso-f3-smoke-') as tmp, \
     patch.object(f3.os.path, 'ismount', return_value=True), patch.object(f3, 'emit'):
    sentinel = Path(tmp, '1.h2w')
    sentinel.write_text('Pre-existing user data')
    directory = f3.TestDirectory(tmp)
    control, writer = os.pipe()
    try:
        write = f3.run_tool(str(binaries / ('f3write-' + arch + '-apple-darwin')),
                            'write', directory, f3.GIB, control, ('--end-at=1',))
        total = sum(directory.files().values())
        assert total == f3.GIB, total
        read = f3.run_tool(str(binaries / ('f3read-' + arch + '-apple-darwin')),
                           'read', directory, total, control)
        assert read.summary(total)['Data LOST'] == 0
        print('Real F3: 1 GiB written and verified; %.1f / %.1f MiB/s' %
              (write.average('write'), read.average('read')))
        with open(Path(directory.path, '1.h2w'), 'r+b') as file:
            file.seek(128)
            value = file.read(1)
            file.seek(128)
            file.write(bytes([value[0] ^ 0xff]))
            file.flush()
            os.fsync(file.fileno())
        damaged = f3.run_tool(str(binaries / ('f3read-' + arch + '-apple-darwin')),
                              'read', directory, total, control)
        assert damaged.summary(total)['Data LOST'] == 1, damaged.tail[-1500:]
        print('Real F3: injected single-byte corruption detected despite successful process exit')
    finally:
        os.close(writer)
        os.close(control)
        directory.cleanup()
    assert sentinel.read_text() == 'Pre-existing user data'
    assert not Path(directory.path).exists()
    print('Cleanup removed test files and preserved the pre-existing 1.h2w file')
