"""Bounded-memory I/O algorithms shared by the signed application's operations.

No device is selected here: Rust validates and locks the requested disk before
starting the privileged supervisor. Tests use ordinary temporary files.
"""
import os
import sys
import time
import hashlib
import subprocess
import tempfile
import fcntl
import ctypes
import json
import errno

BLOCK = 8 * 1024 * 1024
_last_progress = {}

def emit_due(key, current, total):
    now = time.monotonic()
    if current == total or now - _last_progress.get(key, 0) >= .1:
        _last_progress[key] = now
        return True
    return False

def publish(partial, destination):
    if sys.platform == 'darwin':
        # RENAME_EXCL also works on removable filesystems without hard links.
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(os.fsencode(partial), os.fsencode(destination), 4) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), destination)
    else:
        os.link(partial, destination)
        os.unlink(partial)

def open_device(path, flags):
    fd = os.open(path, flags)
    if sys.platform == 'darwin':
        try: fcntl.fcntl(fd, 48, 1)  # F_NOCACHE: verification must read the device.
        except OSError:
            os.close(fd)
            raise
    return fd

def read_exact(reader, size):
    chunks = []
    remaining = size
    while remaining:
        data = reader(remaining)
        if not data:
            raise OSError('Unerwartetes Dateiende: %s Bytes fehlen' % remaining)
        chunks.append(data)
        remaining -= len(data)
    return b''.join(chunks)

def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError('Unvollständiger Schreibzugriff')
        view = view[written:]

def progress(prefix, current, total, extra=None):
    # At most ten progress events/second, plus each exact phase completion.
    if emit_due((prefix, extra), current, total):
        print('%s:%d%s' % (prefix, current, '' if extra is None else ':' + str(extra)), flush=True)

def burn(cfg):
    total = cfg['size']
    if total <= 0: raise ValueError('Leeres Image')
    decoder = None
    errors_file = None
    fd = open_device(cfg['device'], os.O_RDWR)
    try:
        if cfg.get('xz'):
            errors_file = tempfile.TemporaryFile()
            decoder = subprocess.Popen([cfg['xz'], '--threads=2', '-dc', '--', cfg['source']],
                                       stdout=subprocess.PIPE, stderr=errors_file)
            source = decoder.stdout
        else:
            source = open(cfg['source'], 'rb')
        hashes = []
        copied = 0
        with source:
            while copied < total:
                data = read_exact(source.read, min(BLOCK, total - copied))
                write_all(fd, data)
                if cfg.get('verify'): hashes.append((len(data), hashlib.sha256(data).digest()))
                copied += len(data)
                progress('BYTES', copied, total)
            if source.read(1): raise OSError('Image ist seit der Größenprüfung gewachsen')
        if decoder and decoder.wait() != 0:
            errors_file.seek(0)
            raise OSError(errors_file.read(65536).decode('utf-8', errors='replace'))
        os.fsync(fd)
        print('WRITE_SUCCESS', flush=True)
        if cfg.get('verify'):
            os.lseek(fd, 0, os.SEEK_SET)
            checked = 0
            errors = 0
            for size, expected in hashes:
                actual = read_exact(lambda n: os.read(fd, n), size)
                if hashlib.sha256(actual).digest() != expected: errors += 1
                checked += size
                progress('VERIFY', checked, total, errors)
            if checked != total: raise OSError('Unvollständige Verifizierung')
            if errors: raise OSError('Verifizierung: %d fehlerhafte Blöcke' % errors)
            print('VERIFY_SUCCESS', flush=True)
    finally:
        if decoder:
            if decoder.poll() is None: decoder.kill()
            decoder.wait()
        if errors_file: errors_file.close()
        os.close(fd)

def backup(cfg):
    total = cfg['size']
    if total <= 0: raise ValueError('Ungültige Sicherungsgröße')
    destination = cfg['destination']
    partial = destination + '.partial'
    # Exclusive creation protects existing backups and symlink destinations.
    if os.path.lexists(destination): raise FileExistsError(destination)
    # Root is needed only to acquire the raw reader, not to create a backup.
    with open(cfg['device'], 'rb', buffering=0) as source:
        if 'uid' in cfg and os.geteuid() == 0:
            os.setgroups([])
            os.setgid(cfg['gid'])
            os.setuid(cfg['uid'])
        with open(partial, 'xb', buffering=0) as output:
            copied = 0
            while copied < total:
                data = read_exact(source.read, min(BLOCK, total - copied))
                write_all(output.fileno(), data)
                copied += len(data)
                progress('BYTES', copied, total)
            os.fsync(output.fileno())
    # Publish only complete bytes, without overwriting a file created meanwhile.
    publish(partial, destination)

def diagnostic(cfg):
    total = cfg['size']
    if total <= 0: raise ValueError('Ungültige Datenträgergröße')
    full = cfg['mode'] == 'full'
    fd = open_device(cfg['device'], os.O_RDWR if full else os.O_RDONLY)
    try:
        for pattern in ([0, 255] if full else [None]):
            pattern_data = bytes([pattern]) * BLOCK if full else None
            if full:
                started = time.monotonic()
                os.lseek(fd, 0, os.SEEK_SET)
                done = 0
                while done < total:
                    length = min(BLOCK, total - done)
                    write_all(fd, memoryview(pattern_data)[:length])
                    done += length
                    progress('DIAG', done, total, 'write:%d' % pattern)
                os.fsync(fd)
                print('TIMING:write:%d:%.9f' % (total, time.monotonic() - started), flush=True)
            os.lseek(fd, 0, os.SEEK_SET)
            started = time.monotonic()
            done = 0
            while done < total:
                size = min(BLOCK, total - done)
                data = read_exact(lambda n: os.read(fd, n), size)
                if full and data != pattern_data[:size]:
                    mismatch = next(i for i, value in enumerate(data) if value != pattern)
                    raise OSError('Datenfehler an Byte %d (Sektor %d)' % (done + mismatch, (done + mismatch) // 512))
                done += size
                progress('DIAG', done, total, 'read:%s' % (pattern if full else 'scan'))
            print('TIMING:read:%d:%.9f' % (total, time.monotonic() - started), flush=True)
    finally: os.close(fd)

def erase(cfg):
    fd = open_device(cfg['device'], os.O_WRONLY)
    total = cfg['size']
    done = 0
    zeros = bytes(BLOCK)
    try:
        while done < total:
            size = min(BLOCK, total - done)
            data = os.urandom(size) if cfg.get('random') else zeros[:size]
            write_all(fd, data)
            done += size
            progress('BYTES', done, total)
        os.fsync(fd)
    finally: os.close(fd)

def filesystem_backup(cfg):
    destination = cfg['destination']
    partial = destination + '.partial.dmg'
    if os.path.lexists(destination) or os.path.lexists(partial): raise FileExistsError(destination)
    subprocess.run(['/usr/bin/hdiutil', 'create', '-puppetstrings', '-format', 'UDZO',
                    '-volname', cfg['name'], '-srcfolder', cfg['mount'], partial], check=True)
    publish(partial, destination)

def worker(cfg):
    mode = cfg['mode']
    if mode == 'burn': burn(cfg)
    elif mode == 'backup': backup(cfg)
    elif mode == 'full': diagnostic(cfg)
    elif mode in ('surface', 'sample'): surface_scan(cfg)
    elif mode == 'erase': erase(cfg)
    elif mode == 'filesystem_backup': filesystem_backup(cfg)
    elif mode == 'speed': speed(cfg)
    elif mode == 'command': subprocess.run(['/bin/sh', '-c', cfg['script']], stdin=subprocess.DEVNULL, check=True)
    else: raise ValueError('Unbekannter Vorgang: ' + mode)

def diagnostic_event(event_name, **values):
    print(event_name + ':' + json.dumps(values, allow_nan=False), flush=True)


def sample_ranges(total, window=BLOCK, count=16):
    """Deterministic, non-overlapping windows, including both ends of the disk."""
    if total <= window * count:
        return [(0, total)]
    last = total - window
    return [((last * i // (count - 1)) // 512 * 512, window)
            for i in range(count - 1)] + [(last, window)]


def surface_scan(cfg):
    total = cfg['size']
    if total <= 0: raise ValueError('Ungültige Datenträgergröße')
    sampled = cfg.get('mode') == 'sample'
    ranges = sample_ranges(total) if sampled else [(0, total)]
    target = sum(length for _, length in ranges)
    fd = open_device(cfg['device'], os.O_RDONLY)
    processed = readable = bad_bytes = failures = retries = 0
    bad_ranges = []
    started = time.monotonic()

    def update(force=False, phase='reading'):
        elapsed = max(time.monotonic() - started, .000001)
        if force or emit_due('surface', processed, target):
            diagnostic_event('DSTAT', phase=phase, percent=min(99, int(processed * 100 / target)),
                bytes_checked=processed, target_bytes=target, readable_bytes=readable,
                read_mib_s=readable / elapsed / 1048576, errors_found=failures,
                retry_count=retries, sampled=sampled,
                eta_seconds=(target-processed) * elapsed / processed if processed else None)

    def attempt(offset, length):
        nonlocal retries
        # Initial attempt + one retry. Fatal errors (disconnect/EOF/permission)
        # must abort, not manufacture thousands of unreadable regions.
        for attempt_number in range(2):
            try:
                os.lseek(fd, offset, os.SEEK_SET)
                read_exact(lambda n: os.read(fd, n), length)
                return True
            except OSError as error:
                if error.errno not in (errno.EIO, errno.EILSEQ): raise
                update(phase='retrying')
                if attempt_number == 0: retries += 1
        return False

    def check_region(offset, length):
        nonlocal processed, readable, bad_bytes, failures
        if attempt(offset, length):
            processed += length
            readable += length
            update()
        elif length > 65536:
            # Localize to <=64KiB regions; never pretend to know the exact
            # defective sector. Bounded retries avoid endless hangs in bad areas.
            for local in range(0, length, 65536):
                check_region(offset + local, min(65536, length - local))
        else:
            processed += length
            bad_bytes += length
            failures += 1
            if len(bad_ranges) < 256:
                bad_ranges.append(dict(offset=offset, length=length))
            update()

    try:
        update(force=True)
        for offset, length in ranges:
            for local in range(0, length, BLOCK):
                check_region(offset + local, min(BLOCK, length - local))
        elapsed = max(time.monotonic() - started, .000001)
        diagnostic_event('DRESULT', kind='sample' if sampled else 'surface',
            sampled=sampled, complete=True, success=failures == 0,
            bytes_checked=processed, readable_bytes=readable, unreadable_bytes=bad_bytes,
            target_bytes=target, device_bytes=total, coverage_percent=processed * 100 / total,
            errors_found=failures, retry_count=retries, bad_ranges=bad_ranges,
            bad_ranges_truncated=failures > len(bad_ranges),
            read_mib_s=readable / elapsed / 1048576, write_mib_s=0, elapsed_seconds=elapsed)
    finally: os.close(fd)


def speed(cfg):
    profile = cfg.get('speed_profile', 'detailed')
    if profile not in ('quick', 'detailed'): raise ValueError('Unbekanntes Testprofil')
    total = cfg['size']
    if total <= 0: raise ValueError('Ungültige Datenträgergröße')
    # The backend fixes this at 30s. A smaller value supports file-only tests.
    budget = float(cfg.get('seconds', 30))
    if budget <= 0 or budget > 30: raise ValueError('Ungültiges Zeitbudget')
    blocks = (8 * 1024**2,) if profile == 'quick' else (1024**2, 4 * 1024**2, 16 * 1024**2)
    amount = min(total, max(100 * 1024**2, min(total // 30, 50 * 1024**3)))
    rows = []
    fd = open_device(cfg['device'], os.O_RDWR)
    try:
        for index, block in enumerate(blocks):
            data = bytes(block)
            row = dict(block_bytes=block)
            written_extent = 0
            for phase_index, phase in enumerate(('write', 'read')):
                offset = done = 0
                os.lseek(fd, 0, os.SEEK_SET)
                started = time.monotonic()
                extent = (total if phase == 'write' else written_extent) if profile == 'quick' else amount
                while True:
                    elapsed = time.monotonic() - started
                    if profile == 'quick' and done and elapsed >= budget: break
                    if profile == 'detailed' and done >= amount: break
                    if offset == extent:
                        offset = 0
                        os.lseek(fd, 0, os.SEEK_SET)
                    size = min(block, extent - offset)
                    if phase == 'write':
                        write_all(fd, memoryview(data)[:size])
                        written_extent = max(written_extent, offset + size)
                    else:
                        read_exact(lambda n: os.read(fd, n), size)
                    done += size
                    offset += size
                    elapsed = max(time.monotonic() - started, .000001)
                    fraction = min(.99, elapsed / budget) if profile == 'quick' else min(.99, done / amount)
                    if emit_due(('speed', index, phase), done, -1):
                        diagnostic_event('DSTAT', phase=phase, block_bytes=block,
                            percent=int((index * 2 + phase_index + fraction) / (2 * len(blocks)) * 100),
                            bytes_checked=done, errors_found=0,
                            read_mib_s=done / elapsed / 1048576 if phase == 'read' else 0,
                            write_mib_s=done / elapsed / 1048576 if phase == 'write' else 0,
                            eta_seconds=None)
                if phase == 'write':
                    diagnostic_event('DSTAT', phase='synchronizing', block_bytes=block,
                        percent=int((index * 2 + .99) / (2 * len(blocks)) * 100),
                        bytes_checked=done, errors_found=0, eta_seconds=None)
                    os.fsync(fd)
                elapsed = max(time.monotonic() - started, .000001)
                row[phase + '_bytes'] = done
                row[phase + '_seconds'] = elapsed
                row[phase + '_mib_s'] = done / elapsed / 1048576
            rows.append(row)
        read_bytes = sum(row['read_bytes'] for row in rows)
        write_bytes = sum(row['write_bytes'] for row in rows)
        diagnostic_event('DRESULT', kind='speed', profile=profile, complete=True, success=True,
            errors_found=0, bytes_checked=read_bytes, device_bytes=total, speed_results=rows,
            read_mib_s=read_bytes / sum(row['read_seconds'] for row in rows) / 1048576,
            write_mib_s=write_bytes / sum(row['write_seconds'] for row in rows) / 1048576)
    finally: os.close(fd)
