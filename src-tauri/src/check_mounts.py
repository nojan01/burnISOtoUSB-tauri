"""Fail-closed mount validation, including synthesized APFS volumes."""
import plistlib
import subprocess
import sys

def plist(*args):
    result = subprocess.run(['/usr/sbin/diskutil', *args], capture_output=True,
                            check=True, timeout=30)
    return plistlib.loads(result.stdout)

def related_volumes(disk, listing, apfs):
    identifiers = listing.get('AllDisks')
    if not isinstance(identifiers, list) or disk not in identifiers:
        raise ValueError('Datenträgerliste unvollständig')
    result = {v for v in identifiers if v == disk or v.startswith(disk + 's')}
    containers = apfs.get('Containers')
    if not isinstance(containers, list): raise ValueError('APFS-Liste unvollständig')
    for container in containers:
        stores = container.get('PhysicalStores', [])
        if any(s.get('DeviceIdentifier', '').startswith(disk + 's') or
               s.get('DeviceIdentifier') == disk for s in stores):
            for volume in container.get('Volumes', []):
                result.add(volume['DeviceIdentifier'])
    return sorted(result)

def check(disk):
    targets = related_volumes(disk, plist('list', '-plist', disk), plist('apfs', 'list', '-plist'))
    for target in targets:
        info = plist('info', '-plist', target)
        if info.get('DeviceIdentifier') != target: raise ValueError('Gerätekennung hat sich geändert')
        if info.get('MountPoint') or info.get('Mounted') is True:
            raise ValueError('Volume weiterhin eingehängt: ' + target)

if __name__ == '__main__':
    try: check(sys.argv[1])
    except Exception as error:
        sys.exit('Aushängen konnte nicht bestätigt werden: ' + str(error))
