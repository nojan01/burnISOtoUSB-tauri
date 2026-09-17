"""F3 controller regressions. No attached disk is written or unmounted."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('f3', ROOT / 'src-tauri/src/f3_worker.py')
f3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f3)


def report(ok=2048, bad=0):
    return (f'Data OK: 1 MB ({ok} sectors)\nData LOST: 0 MB ({bad} sectors)\n'
            f'Corrupted: 0 MB ({bad} sectors)\nSlightly changed: 0 MB (0 sectors)\n'
            'Overwritten: 0 MB (0 sectors)\nAverage sequential read speed: 100.00 MB/s\n').encode()


class F3Tests(unittest.TestCase):
    def test_zero_exit_with_corrupt_data_is_not_success(self):
        out = f3.Output()
        out.feed(report(2047, 1))
        self.assertEqual(out.summary(1048576)['Data LOST'], 1)
        self.assertEqual(out.average('read'), 100)

    def test_missing_empty_and_inconsistent_reports_fail_closed(self):
        for data, written in [(b'', 1024), (report(), 2097152), (report(0), 0),
                              (report().replace(b'(0 sectors)', b'(1 sectors)', 1), 1049088)]:
            out = f3.Output()
            out.feed(data)
            with self.assertRaises(ValueError): out.summary(written)

    def test_streamed_progress_and_sticky_write_error(self):
        out = f3.Output()
        out.feed(b'Creating file 1.h2w ... 23.45% -- 1.50 GB/s')
        self.assertEqual(out.percent, 23.45)
        self.assertEqual(out.speed, 1536)
        out.feed(b'Write fail')
        out.feed(b'ure: Device not configured\n')
        out.feed(b'x' * 100000)
        self.assertTrue(out.failed)
        self.assertLessEqual(len(out.tail), 65536)

    def test_apfs_membership_never_crosses_physical_disks(self):
        listing = {'AllDisks': ['disk4', 'disk4s1', 'disk40s1']}
        apfs = {'Containers': [
            {'PhysicalStores': [{'DeviceIdentifier': 'disk4s1'}],
             'Volumes': [{'DeviceIdentifier': 'disk5s1'}, {'DeviceIdentifier': 'disk5s2', 'Roles': ['System']}]},
            {'PhysicalStores': [{'DeviceIdentifier': 'disk4s1'}, {'DeviceIdentifier': 'disk8s1'}],
             'Volumes': [{'DeviceIdentifier': 'disk9s1'}]}]}
        self.assertEqual(f3.volume_ids('disk4', listing, apfs), ['disk4', 'disk4s1', 'disk5s1'])

    def test_selection_rejects_reused_identifier_with_different_uuid(self):
        with patch.object(f3, 'volumes', return_value=[{'id': 'disk5s1', 'uuid': 'new'}]):
            with self.assertRaises(ValueError):
                f3.selected_volume({'disk_id': 'disk4', 'volume_id': 'disk5s1', 'volume_uuid': 'old'})

    def test_cleanup_preserves_existing_files_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(f3.os.path, 'ismount', return_value=True):
            sentinel = Path(tmp, '1.h2w')
            sentinel.write_text('existing data')
            directory = f3.TestDirectory(tmp)
            Path(directory.path, '1.h2w').write_bytes(b'test')
            directory.cleanup()
            self.assertEqual(sentinel.read_text(), 'existing data')
            directory = f3.TestDirectory(tmp)
            Path(directory.path, '1.h2w').symlink_to(sentinel)
            with self.assertRaises(ValueError): directory.cleanup()
            self.assertEqual(sentinel.read_text(), 'existing data')

    def test_replaced_mount_is_not_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(f3.os.path, 'ismount', return_value=True):
            mount = Path(tmp, 'mount'); mount.mkdir()
            directory = f3.TestDirectory(str(mount))
            mount.rename(Path(tmp, 'old'))
            mount.mkdir()
            replacement = mount / directory.name
            replacement.mkdir(); (replacement / '1.h2w').write_text('replacement')
            with self.assertRaises(OSError): directory.cleanup()
            self.assertEqual((replacement / '1.h2w').read_text(), 'replacement')

    def test_appledouble_is_cleaned_but_not_counted_as_test_data(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(f3.os.path, 'ismount', return_value=True):
            directory = f3.TestDirectory(tmp)
            Path(directory.path, '1.h2w').write_bytes(b'x' * 512)
            Path(directory.path, '._1.h2w').write_bytes(b'metadata')
            self.assertEqual(directory.files(), {'1.h2w':512})
            directory.cleanup()
            self.assertFalse(Path(directory.path).exists())

    def test_cancel_or_app_eof_stops_and_reaps_silent_child(self):
        for send_cancel in (True, False):
            with tempfile.TemporaryDirectory() as tmp, patch.object(f3.os.path, 'ismount', return_value=True), patch.object(f3, 'emit'):
                directory = f3.TestDirectory(tmp)
                executable = Path(tmp, 'silent')
                executable.write_text('#!/bin/sh\nexec /bin/sleep 20\n'); executable.chmod(0o755)
                read_fd, write_fd = os.pipe()
                if send_cancel: os.write(write_fd, b'CANCEL\n')
                os.close(write_fd)
                try:
                    with self.assertRaises(f3.Cancelled):
                        f3.run_tool(str(executable), 'write', directory, 1024, read_fd)
                finally:
                    os.close(read_fd)
                    directory.cleanup()
                self.assertFalse(Path(directory.path).exists())

    def test_app_closed_still_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(f3.os.path, 'ismount', return_value=True):
            volume = {'id': 'disk5s1', 'uuid': 'u', 'mount_point': tmp, 'free_bytes': 2**30}
            with patch.object(f3, 'selected_volume', return_value=volume), \
                 patch.object(f3, 'run_tool', side_effect=BrokenPipeError()), \
                 patch.object(f3, 'emit', side_effect=BrokenPipeError()):
                with self.assertRaises(BrokenPipeError): f3.run({'f3write': '/unused'})
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == '__main__': unittest.main()
