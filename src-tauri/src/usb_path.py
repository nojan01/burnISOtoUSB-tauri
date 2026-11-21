"""Resolve USB evidence from the selected IOMedia's IOService ancestry."""
import json
import plistlib
import subprocess
import sys


# Manufacturer byte of a raw NAND READ ID response (address 00h).
NAND_MAKERS = {0x2c: 'Micron', 0xec: 'Samsung', 0xad: 'SK hynix',
               0x98: 'Toshiba / Kioxia', 0x45: 'SanDisk', 0xc2: 'Macronix'}


def flash_components(path):
    controller, nand = {}, {}
    for node in reversed(path):
        for key, target, field in [
            ('Flash Controller Manufacturer', controller, 'manufacturer'),
            ('Flash Controller Model', controller, 'model'),
            ('NAND Manufacturer', nand, 'manufacturer'), ('NAND Model', nand, 'model')]:
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                target.setdefault(field, value.strip())
        value = node.get('NAND ID')
        if isinstance(value, bytes) and 2 <= len(value) <= 8 and 'raw_id' not in nand:
            nand['raw_id'] = value.hex(' ')
            if value[0] in NAND_MAKERS:
                nand.setdefault('manufacturer', NAND_MAKERS[value[0]])
    return {'controller': controller or None, 'nand': nand or None}


def identify(nodes, disk):
    def visit(node, device, controller, path):
        kind = node.get('IOObjectClass', '')
        if 'idVendor' in node and 'idProduct' in node and 'USB' in kind:
            device = node
            path = ()
        if kind.upper().endswith(('XHCI', 'EHCI', 'OHCI')) or kind == 'IOUSBHostController':
            controller = kind
        path = (*path, node) if device else (node,)
        if node.get('BSD Name') == disk and node.get('Whole') is True:
            result = {'flash_components': flash_components(path)}
            if device:
                info = {}
                for key, field in [('USB Product Name', 'product_name'), ('USB Vendor Name', 'manufacturer'),
                                   ('USB Serial Number', 'serial_number')]:
                    if device.get(key):
                        info[field] = device[key]
                for key, field in [('idVendor', 'vendor_id'), ('idProduct', 'product_id'), ('locationID', 'location_id')]:
                    if isinstance(device.get(key), int):
                        info[field] = format(device[key], '#06x')
                result['usb_info'] = info
                if controller:
                    result['controller_info'] = {'host_controller': controller}
            return result
        for child in node.get('IORegistryEntryChildren', []):
            result = visit(child, device, controller, path)
            if result is not None:
                return result
        return None

    for node in ([nodes] if isinstance(nodes, dict) else nodes):
        result = visit(node, None, None, ())
        if result is not None:
            return result
    return {}


if __name__ == '__main__':
    tree = subprocess.check_output(['/usr/sbin/ioreg', '-a', '-l', '-p', 'IOService'], timeout=30)
    print(json.dumps(identify(plistlib.loads(tree), sys.argv[1])))
