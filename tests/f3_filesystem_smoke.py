"""Opt-in macOS test: fill/verify/clean only fresh 128-MiB disk images.

Uses DiskManagement, so run outside an app sandbox. No physical device is
formatted, written or unmounted. The production physical-disk selection is
replaced only within this test; all file I/O and cleanup use the real controller.
"""
import importlib.util
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('f3', ROOT / 'src-tauri/src/f3_worker.py')
f3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f3)
arch = 'aarch64' if platform.machine() == 'arm64' else 'x86_64'
binaries = ROOT / 'src-tauri/binaries'


def command(*args):
    result = subprocess.run(args, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(str(args) + ': ' + result.stderr.decode(errors='replace'))
    return result.stdout


with tempfile.TemporaryDirectory(prefix='burniso-f3-filesystems-') as tmp:
    for index, filesystem in enumerate(sys.argv[1:] or ['APFS', 'HFS+', 'ExFAT', 'MS-DOS FAT32']):
        image = str(Path(tmp, 'test-' + str(index) + '.dmg'))
        label = 'F3SMOKE' + str(index)
        # hdiutil cannot create ExFAT directly on every macOS version.
        command('/usr/bin/hdiutil', 'create', '-size', '128m', '-fs', filesystem if filesystem in ('APFS', 'HFS+') else 'HFS+',
                '-volname', label, image)
        entities = plistlib.loads(command('/usr/bin/hdiutil', 'attach', '-nobrowse', '-plist', image))['system-entities']
        device = entities[0]['dev-entry']
        try:
            mount = next(e['mount-point'] for e in entities if e.get('mount-point'))
            assert mount == '/Volumes/' + label, mount
            if filesystem not in ('APFS', 'HFS+'):
                target = next(e['dev-entry'] for e in entities if e.get('mount-point') == mount)
                attached = plistlib.loads(command('/usr/bin/hdiutil', 'info', '-plist'))['images']
                assert any(os.path.realpath(i['image-path']) == os.path.realpath(image)
                           and any(e.get('dev-entry') == target for e in i['system-entities'])
                           for i in attached), 'Target is not part of our temporary image'
                command('/usr/sbin/diskutil', 'eraseVolume', filesystem, label, target)
            info = plistlib.loads(command('/usr/sbin/diskutil', 'info', '-plist', mount))
            sentinel = Path(mount, '1.h2w')
            sentinel.write_text('Existing file must survive')
            fs = os.statvfs(mount)
            volume = {'id':info['DeviceIdentifier'], 'uuid':info['VolumeUUID'],
                      'name':info['VolumeName'], 'mount_point':mount, 'free_bytes':fs.f_bavail * fs.f_frsize}
            events = []
            control, writer = os.pipe()
            try:
                with patch.object(f3, 'selected_volume', return_value=volume), \
                     patch.object(f3, 'emit', side_effect=lambda kind, data: events.append((kind, data))):
                    f3.run({'f3write':str(binaries / ('f3write-' + arch + '-apple-darwin')),
                            'f3read':str(binaries / ('f3read-' + arch + '-apple-darwin'))}, control)
            finally:
                os.close(writer)
                os.close(control)
            result = next(data for kind, data in events if kind == 'DRESULT')
            assert result['success'] and result['bytes_checked'] > 16 * 1024**2, result
            assert sentinel.read_text() == 'Existing file must survive'
            assert not [p for p in Path(mount).iterdir() if '.burniso-f3-' in p.name]
            print(filesystem, 'passed: %.1f MiB filled, verified, cleaned' % (result['bytes_checked'] / 1024**2), flush=True)
        finally:
            command('/usr/bin/hdiutil', 'detach', device)
