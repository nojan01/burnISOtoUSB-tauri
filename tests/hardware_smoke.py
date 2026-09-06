"""Explicitly opt-in, DESTRUCTIVE smoke test. Never invoked by the unit suite.

Requires --erase DEVICE:EXACT_BYTES:MEDIA_NAME for every authorized device.
Rejects internal disks and media >128GB. Writes only the first 64MiB+512B;
the partition map is destroyed and the medium must be reformatted afterwards.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1] / 'src-tauri/src'
sys.path.insert(0, str(ROOT))
import check_mounts

def run_worker(config):
    script = (ROOT / 'worker.py').read_text() + '\n' + (ROOT / 'supervisor.py').read_text()
    child = subprocess.Popen([sys.executable, '-u', '-c', script, json.dumps(config)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Keep stdin open. EOF is deliberately treated as parent failure/cancel.
    assert child.stdout is not None
    done = False
    for line in child.stdout:
        if line.strip() == b'DONE': done = True
    error = child.stderr.read().decode(errors='replace')
    status = child.wait()
    child.stdin.close()
    if status or not done: raise RuntimeError('Worker failed: ' + error)

def validate(disk, size, name):
    info = check_mounts.plist('info', '-plist', disk)
    assert info.get('DeviceIdentifier') == disk and info.get('WholeDisk') is True
    assert info.get('Internal') is False and info.get('VirtualOrPhysical') == 'Physical'
    assert info.get('TotalSize') == size and info.get('MediaName') == name
    assert 0 < size < 128 * 1024**3 and info.get('Writable') is True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--erase', action='append', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit('Administrator privileges required')
    with tempfile.TemporaryDirectory(prefix='burniso-hardware-smoke-') as temp:
        root = Path(temp)
        size = 64 * 1024**2 + 512
        source = root / 'source.img'
        with source.open('wb') as file:
            block = os.urandom(1024**2)
            for _ in range(64): file.write(block)
            file.write(os.urandom(512))
        compressed = root / 'source.img.xz'
        compressed.write_bytes(lzma.compress(source.read_bytes()))
        expected = hashlib.sha256(source.read_bytes()).digest()
        xz = '/opt/homebrew/bin/xz'
        for target in args.erase:
            disk, capacity, name = target.split(':', 2)
            capacity = int(capacity)
            if not disk.startswith('disk') or not disk[4:].isdigit(): raise ValueError('Invalid disk identifier')
            validate(disk, capacity, name)
            print(f'TEST {disk}: {name}, {capacity} bytes (destructive prefix test)', flush=True)
            subprocess.run(['/usr/sbin/diskutil','unmountDisk',disk], check=True, stdout=subprocess.DEVNULL)
            check_mounts.check(disk)
            validate(disk, capacity, name)
            device = '/dev/r' + disk
            for image, decoder in [(source, None), (compressed, xz)]:
                validate(disk, capacity, name)
                check_mounts.check(disk)
                start = time.monotonic()
                run_worker(dict(mode='burn', source=str(image), device=device, size=size, xz=decoder, verify=True))
                print(f'PASS {disk}: {image.name}, write+verify {time.monotonic()-start:.2f}s', flush=True)
            backup = root / (disk + '.img')
            run_worker(dict(mode='backup', device=device, size=size, destination=str(backup)))
            assert hashlib.sha256(backup.read_bytes()).digest() == expected
            print(f'PASS {disk}: exact {size}-byte backup', flush=True)
            run_worker(dict(mode='full', device=device, size=size))
            run_worker(dict(mode='surface', device=device, size=size))
            print(f'PASS {disk}: 00/FF full-byte verification + surface read including tail', flush=True)
            print(f'NOTICE {disk}: first {size} bytes overwritten; partition map destroyed.', flush=True)

if __name__ == '__main__': main()
