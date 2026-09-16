"""F3 file tests: unprivileged, confined to a new directory on a validated volume.

The controller stays alive while F3 runs so cancellation/EOF stops and reaps F3
before cleaning up. Directory descriptors prevent an unplug/replug from sending
writes or cleanup to a replacement mount point. No raw device is opened.
"""
import json
import os
import plistlib
import re
import selectors
import stat
import subprocess
import sys
import time
import uuid

GIB = 1024 ** 3


def plist(*args):
    p = subprocess.run(['/usr/sbin/diskutil', *args], capture_output=True,
                       check=True, timeout=30)
    return plistlib.loads(p.stdout)


def volume_ids(disk, listing, apfs):
    def belongs(identifier):
        return identifier == disk or identifier.startswith(disk + 's')
    if disk not in listing.get('AllDisks', []):
        raise ValueError('Datenträger nicht mehr vorhanden')
    ids = {v for v in listing['AllDisks'] if belongs(v)}
    for container in apfs.get('Containers', []):
        stores = [s['DeviceIdentifier'] for s in container.get('PhysicalStores', [])]
        # Never exercise another physical disk through a spanning container.
        if stores and all(belongs(s) for s in stores):
            ids.update(v['DeviceIdentifier'] for v in container.get('Volumes', [])
                       if not set(v.get('Roles', [])).intersection(
                           {'System', 'Data', 'Preboot', 'Recovery', 'VM'}))
    return sorted(ids)


def volumes(disk):
    if not re.fullmatch(r'disk[0-9]+', disk):
        raise ValueError('Ungültiger Datenträger')
    physical = plist('info', '-plist', disk)
    if (physical.get('DeviceIdentifier') != disk or physical.get('WholeDisk') is not True
            or physical.get('VirtualOrPhysical') != 'Physical'):
        raise ValueError('Kein physischer Datenträger')
    if not (physical.get('Internal') is False or physical.get('RemovableMedia') is True):
        raise ValueError('Nur externe Datenträger oder Wechselmedien erlaubt')
    ids = volume_ids(disk, plist('list', '-plist', disk), plist('apfs', 'list', '-plist'))
    result = []
    for identifier in ids:
        info = plist('info', '-plist', identifier)
        mount = info.get('MountPoint')
        vol_uuid = info.get('VolumeUUID')
        if (info.get('DeviceIdentifier') != identifier or not mount or not vol_uuid
                or info.get('Writable') is not True or info.get('WritableVolume') is not True
                or info.get('ReadOnlyVolume') is True):
            continue
        # stat + ismount also reject stale mount-point directories on the system disk.
        if (not os.path.ismount(mount) or os.path.islink(mount)
                or os.stat(mount).st_dev == os.stat('/').st_dev):
            continue
        fs = os.statvfs(mount)
        result.append({'id': identifier, 'uuid': vol_uuid, 'name': info.get('VolumeName', identifier),
                       'mount_point': mount, 'free_bytes': fs.f_bavail * fs.f_frsize})
    return result


def selected_volume(cfg):
    for volume in volumes(cfg['disk_id']):
        if volume['id'] == cfg['volume_id'] and volume['uuid'] == cfg['volume_uuid']:
            return volume
    raise ValueError('Das gewählte Volume ist nicht mehr verfügbar. Bitte neu auswählen.')


def identity(st):
    return st.st_dev, st.st_ino


class TestDirectory:
    def __init__(self, mount):
        self.mount = mount
        self.name = '.burniso-f3-' + uuid.uuid4().hex
        self.path = os.path.join(mount, self.name)
        self.root = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.fd = None
        try:
            self.root_identity = identity(os.fstat(self.root))
            self.check()
            os.mkdir(self.name, 0o700, dir_fd=self.root)
            self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=self.root)
        except BaseException:
            os.close(self.root)
            raise

    def check(self):
        if identity(os.stat(self.mount, follow_symlinks=False)) != self.root_identity:
            raise OSError('Volume wurde getrennt oder ersetzt')
        if not os.path.ismount(self.mount):
            raise OSError('Volume ist nicht mehr eingehängt')

    def files(self, include_metadata=False):
        result = {}
        for name in os.listdir(self.fd):
            s = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            # macOS creates AppleDouble sidecars on FAT/exFAT. They belong to
            # these new files but are not part of F3's pattern/data byte counts.
            if not re.fullmatch(r'(?:\._)?[1-9][0-9]*\.h2w', name) or not stat.S_ISREG(s.st_mode):
                raise ValueError('Unerwarteter Eintrag im Testordner: ' + name)
            if include_metadata or not name.startswith('._'):
                result[name] = s.st_size
        return result

    def cleanup(self):
        try:
            # Unlink only our own regular test files, never traverse subdirectories.
            self.check()
            for name in self.files(include_metadata=True):
                try:
                    os.unlink(name, dir_fd=self.fd)
                except FileNotFoundError:
                    # Deleting the data file can also remove its AppleDouble.
                    if not name.startswith('._'):
                        raise
            if identity(os.stat(self.name, dir_fd=self.root, follow_symlinks=False)) != identity(os.fstat(self.fd)):
                raise OSError('Testordner wurde ersetzt')
            os.rmdir(self.name, dir_fd=self.root)
        finally:
            if self.fd is not None:
                os.close(self.fd)
            os.close(self.root)


def speed_mib(number, unit):
    return float(number) * {'Byte': 1, 'Bytes': 1, 'KB': 1024, 'MB': 1024**2,
                            'GB': 1024**3, 'TB': 1024**4}.get(unit, 0) / 1024**2


class Output:
    def __init__(self):
        self.tail = ''
        self.failed = False
        self.percent = 0.0
        self.speed = 0.0

    def feed(self, data):
        text = self.tail[-1024:] + data.decode('utf-8', errors='replace')
        self.failed |= any(s in text for s in ('Write failure:', 'WARNING:', 'NOT fully read', 'Missing file '))
        matches = list(re.finditer(r'([0-9.]+)% -- ([0-9.]+) (Bytes?|KB|MB|GB|TB)/s', text))
        if matches:
            self.percent = min(100.0, float(matches[-1][1]))
            self.speed = speed_mib(matches[-1][2], matches[-1][3])
        self.tail = (self.tail + data.decode('utf-8', errors='replace'))[-65536:]

    def average(self, phase):
        match = re.search(r'Average sequential ' + phase + r' speed:\s*([0-9.]+) (Bytes?|KB|MB|GB|TB)/s', self.tail)
        if not match:
            raise ValueError('F3 hat keinen vollständigen Geschwindigkeitsbericht geliefert')
        return speed_mib(match[1], match[2])

    def summary(self, written):
        counts = {}
        for key in ('Data OK', 'Data LOST', 'Corrupted', 'Slightly changed', 'Overwritten'):
            found = re.findall(re.escape(key) + r':[^\n]*\(([0-9]+) sectors?\)', self.tail)
            if len(found) != 1:
                raise ValueError('F3-Prüfbericht fehlt oder ist unvollständig: ' + key)
            counts[key] = int(found[0])
        total = counts['Data OK'] + counts['Data LOST']
        if (total * 512 != written or total == 0 or
                counts['Data LOST'] != sum(counts[k] for k in ('Corrupted', 'Slightly changed', 'Overwritten'))):
            raise ValueError('F3 hat nicht alle geschriebenen Testdaten geprüft')
        return counts


class Cancelled(Exception):
    pass


def emit(kind, data):
    print(kind + ':' + json.dumps(data), flush=True)


def run_tool(binary, phase, directory, target, control, extra_args=()):
    directory.check()
    # Use inherited cwd anchored to an open descriptor, not a mount path.
    saved_cwd = os.open('.', os.O_RDONLY)
    try:
        os.fchdir(directory.fd)
        child = subprocess.Popen([binary, '--show-progress=1', *extra_args, '.'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env={**os.environ, 'LC_ALL': 'C'})
    finally:
        os.fchdir(saved_cwd)
        os.close(saved_cwd)
    output = Output()
    last_emit = 0
    pending = b''
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ, 'output')
            selector.register(control, selectors.EVENT_READ, 'control')
            eof = False
            while not eof or child.poll() is None:
                for key, _ in selector.select(0.2):
                    data = os.read(key.fd, 8192)
                    if key.data == 'control':
                        pending += data
                        if not data or b'CANCEL\n' in pending:
                            raise Cancelled('F3-Test abgebrochen')
                        pending = pending[-64:]
                    elif data:
                        output.feed(data)
                    else:
                        eof = True
                        selector.unregister(child.stdout)
                if time.monotonic() - last_emit >= 0.5:
                    directory.check()
                    if output.failed:
                        raise OSError('F3 meldet einen Ein-/Ausgabefehler: ' + output.tail[-2000:])
                    p = output.percent
                    emit('DSTAT', {'kind': 'f3', 'phase': phase,
                                  'percent': min(99, int(p / 2 + (50 if phase == 'read' else 0))),
                                  'target_bytes': target, 'bytes_checked': int(target * p / 100),
                                  phase + '_mib_s': output.speed})
                    last_emit = time.monotonic()
            code = child.wait()
        if code or output.failed:
            raise OSError('F3 fehlgeschlagen: ' + output.tail[-2000:])
        return output
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()


def run(cfg, control=0):
    volume = selected_volume(cfg)
    if volume['free_bytes'] < 16 * 1024**2:
        raise ValueError('Mindestens 16 MiB freier Speicher erforderlich')
    directory = TestDirectory(volume['mount_point'])
    result = None
    failure = None
    try:
        # Revalidate UUID and membership after opening the directory, before writing.
        fresh = selected_volume(cfg)
        if any(fresh[k] != volume[k] for k in ('id', 'uuid', 'mount_point')):
            raise ValueError('Volume hat sich geändert')
        write = run_tool(cfg['f3write'], 'write', directory, volume['free_bytes'], control)
        files = directory.files()
        written = sum(files.values())
        if written == 0 or written % 512:
            raise ValueError('Keine vollständigen F3-Testdaten geschrieben')
        selected_volume(cfg)
        read = run_tool(cfg['f3read'], 'read', directory, written, control)
        if directory.files() != files:
            raise ValueError('Testdateien wurden während der Prüfung verändert')
        counts = read.summary(written)
        result = {'kind': 'f3', 'complete': True, 'success': counts['Data LOST'] == 0,
                  'bytes_checked': written, 'good_bytes': counts['Data OK'] * 512,
                  'errors_found': counts['Data LOST'], 'corrupted_sectors': counts['Corrupted'],
                  'changed_sectors': counts['Slightly changed'], 'overwritten_sectors': counts['Overwritten'],
                  'volume': volume['name'], 'mount_point': volume['mount_point'],
                  'initial_free_bytes': volume['free_bytes'],
                  'write_mib_s': write.average('write'), 'read_mib_s': read.average('read')}
    except Exception as exc:
        failure = exc
    finally:
        try:
            emit('DSTAT', {'kind': 'f3', 'phase': 'cleanup', 'percent': 99})
        except BrokenPipeError:
            pass  # App closed: still remove test files after stopping F3.
        try:
            directory.cleanup()
        except Exception as exc:
            cleanup_error = 'Testdateien konnten nicht entfernt werden: ' + directory.path + ' (' + str(exc) + ')'
            failure = RuntimeError((str(failure) + '\n' if failure else '') + cleanup_error)
    if failure:
        raise failure
    emit('DRESULT', result)


if __name__ == '__main__':
    try:
        config = json.loads(sys.argv[1])
        if config.get('action') == 'list':
            print(json.dumps(volumes(config['disk_id'])))
        else:
            run(config)
            print('DONE', flush=True)
    except Exception as error:
        print(str(error), file=sys.stderr, flush=True)
        sys.exit(1)
