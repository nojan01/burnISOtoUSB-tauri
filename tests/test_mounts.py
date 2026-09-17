import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mounts', Path(__file__).resolve().parents[1] / 'src-tauri/src/check_mounts.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MountTests(unittest.TestCase):
    def test_physical_and_synthesized_volumes_are_checked(self):
        result = m.related_volumes('disk4', {'AllDisks':['disk4','disk4s1','disk4s2','disk40s1']}, {'Containers':[
            {'PhysicalStores':[{'DeviceIdentifier':'disk4s2'}], 'Volumes':[{'DeviceIdentifier':'disk8s1'}]},
            {'PhysicalStores':[{'DeviceIdentifier':'disk40s2'}], 'Volumes':[{'DeviceIdentifier':'disk9s1'}]}]})
        self.assertEqual(result, ['disk4','disk4s1','disk4s2','disk8s1'])

    def test_unknown_or_incomplete_inventory_fails_closed(self):
        for listing, apfs in [({}, {}), ({'AllDisks':['disk5']},{'Containers':[]}), ({'AllDisks':['disk4']},{})]:
            with self.assertRaises(ValueError): m.related_volumes('disk4', listing, apfs)

    def test_mounted_partition_refuses_raw_access(self):
        values = [{'AllDisks':['disk4','disk4s1']}, {'Containers':[]}, {'DeviceIdentifier':'disk4'}, {'DeviceIdentifier':'disk4s1','MountPoint':'/Volumes/Test'}]
        with patch.object(m, 'plist', side_effect=values), self.assertRaises(ValueError): m.check('disk4')

    def test_command_failure_refuses_raw_access(self):
        with patch.object(m, 'plist', side_effect=subprocess.CalledProcessError(1,'diskutil')), self.assertRaises(subprocess.CalledProcessError): m.check('disk4')

if __name__ == '__main__': unittest.main()
