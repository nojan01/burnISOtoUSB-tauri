"""IOKit service IDs identify an attachment for the lifetime of the media object."""
import ctypes


def media_identity(disk):
    kit = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
    kit.IOBSDNameMatching.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p]
    kit.IOBSDNameMatching.restype = ctypes.c_void_p
    kit.IOServiceGetMatchingService.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    kit.IOServiceGetMatchingService.restype = ctypes.c_uint
    match = kit.IOBSDNameMatching(0, 0, disk.encode('ascii'))
    if not match:
        raise ValueError('Datenträger nicht verfügbar')
    service = kit.IOServiceGetMatchingService(0, match)
    if not service:
        raise ValueError('Datenträger nicht verfügbar')
    try:
        identifier = ctypes.c_uint64()
        if kit.IORegistryEntryGetRegistryEntryID(service, ctypes.byref(identifier)) or not identifier.value:
            raise ValueError('Geräteidentität nicht verfügbar')
        return str(identifier.value)
    finally:
        kit.IOObjectRelease(service)


def verify_media(disk, expected):
    if media_identity(disk) != expected:
        raise ValueError('Datenträger gewechselt. Bitte erneut auswählen und bestätigen.')
