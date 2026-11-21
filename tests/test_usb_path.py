import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src-tauri/src'))
from usb_path import identify


class UsbPathTests(unittest.TestCase):
    def test_sibling_bridges_and_similar_disk_names(self):
        def bridge(vendor, disk):
            return {'IOObjectClass': 'IOUSBHostDevice', 'USB Vendor Name': vendor,
                    'idVendor': 1, 'idProduct': 2, 'IORegistryEntryChildren': [
                        {'BSD Name': disk, 'Whole': True}]}
        tree = [{'IOObjectClass': 'AppleUSBXHCI', 'IORegistryEntryChildren': [
            bridge('Fresco Logic', 'disk16'), bridge('Other', 'disk1')]}]
        self.assertEqual(identify(tree, 'disk1')['usb_info']['manufacturer'], 'Other')
        self.assertEqual(identify(tree, 'disk1')['controller_info']['host_controller'], 'AppleUSBXHCI')
        self.assertEqual(identify(tree, 'disk6'), {})

    def test_nand_id_and_controller_evidence_are_independent(self):
        medium = {'BSD Name': 'disk1', 'Whole': True, 'NAND ID': bytes.fromhex('2c 84')}
        device = {'IOObjectClass': 'IOUSBHostDevice', 'idVendor': 17, 'idProduct': 1,
                  'USB Vendor Name': 'Bridge vendor', 'IORegistryEntryChildren': [medium]}
        result = identify(device, 'disk1')['flash_components']
        self.assertIsNone(result['controller'])
        self.assertEqual(result['nand'], {'manufacturer': 'Micron', 'raw_id': '2c 84'})
        medium['Flash Controller Manufacturer'] = 'Reported maker'
        medium['NAND ID'] = bytes.fromhex('ff 01')
        result = identify(device, 'disk1')['flash_components']
        self.assertEqual(result['controller']['manufacturer'], 'Reported maker')
        self.assertEqual(result['nand'], {'raw_id': 'ff 01'})
