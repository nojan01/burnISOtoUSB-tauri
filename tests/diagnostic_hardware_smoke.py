"""Opt-in DESTRUCTIVE diagnostic test; never run by the unit suite.

Every target requires --erase diskN:EXACT_BYTES:EXACT_MEDIA_NAME. Quick speed
tests overwrite the beginning (possibly all) of each medium, destroying its
partition map. No formatting or partition recovery is attempted.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time

from hardware_smoke import ROOT, validate, check_mounts


def measure(config):
    script = (ROOT / 'worker.py').read_text() + '\n' + (ROOT / 'supervisor.py').read_text()
    child = subprocess.Popen([sys.executable, '-I', '-u', '-c', script, json.dumps(config)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, cwd=ROOT)
    timed_out = threading.Event()

    def cancel():
        timed_out.set()
        # EOF tells the supervisor to kill/reap the entire worker group.
        child.stdin.close()

    timer = threading.Timer(900, cancel)
    timer.start()
    result, done, errors = None, False, []
    last_log = 0
    try:
        for raw in child.stdout:
            line = raw.decode(errors='replace').strip()
            if line == 'DONE':
                done = True
            elif line.startswith('DRESULT:'):
                result = json.loads(line.split(':', 1)[1])
            elif line.startswith('DSTAT:'):
                if time.monotonic() - last_log >= 15:
                    print(line, flush=True)
                    last_log = time.monotonic()
            else:
                errors.append(line)
        status = child.wait()
    finally:
        timer.cancel()
        if not child.stdin.closed:
            child.stdin.close()
        child.wait()
        child.stdout.close()
    if timed_out.is_set() or status or not done or not result or not result.get('complete'):
        raise RuntimeError(f'Incomplete diagnostic: exit={status}, timeout={timed_out.is_set()}, {errors}')
    if not result.get('success'):
        raise RuntimeError('Diagnostic detected media errors: ' + json.dumps(result))
    if config['mode'] == 'surface':
        assert result['readable_bytes'] == config['size']
    print('PASS ' + config['device'] + ' ' + json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--erase', action='append', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Administrator privileges required')
    targets = []
    for target in args.erase:
        disk, capacity, name = target.split(':', 2)
        if not disk.startswith('disk') or not disk[4:].isdigit():
            raise ValueError('Invalid disk identifier')
        capacity = int(capacity)
        validate(disk, capacity, name)
        targets.append((disk, capacity, name))
    for disk, capacity, name in targets:
        print(f'TEST {disk}: {name}, {capacity} bytes; PARTITION MAP WILL BE DESTROYED', flush=True)
        validate(disk, capacity, name)
        subprocess.run(['/usr/sbin/diskutil', 'unmountDisk', disk], check=True)
        modes = [('speed', 'quick'), ('sample', 'quick')]
        if capacity <= 8 * 1024**3:
            modes += [('speed', 'detailed'), ('surface', 'quick')]
        try:
            for mode, profile in modes:
                validate(disk, capacity, name)
                check_mounts.check(disk)
                print(f'START {disk}: {mode}/{profile}', flush=True)
                measure(dict(mode=mode, speed_profile=profile, seconds=30,
                             device='/dev/r' + disk, size=capacity))
        finally:
            subprocess.run(['/usr/sbin/diskutil', 'mountDisk', disk], check=False)
        print(f'NOTICE {disk}: overwritten by speed test; reformat before reuse.', flush=True)


if __name__ == '__main__':
    main()
