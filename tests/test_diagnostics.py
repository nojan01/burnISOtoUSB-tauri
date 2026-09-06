import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('worker_diagnostics', Path(__file__).resolve().parents[1] / 'src-tauri/src/worker.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='burniso-diagnostic-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'device.img'

    def capture(self, function, **config):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream): function(dict(device=str(self.path), **config))
        events = [(kind, json.loads(data)) for line in stream.getvalue().splitlines()
                  for kind, data in [line.split(':', 1)] if kind in ('DSTAT', 'DRESULT')]
        self.assertEqual(events[-1][0], 'DRESULT')
        return events[-1][1], [data for kind, data in events if kind == 'DSTAT']

    def test_complete_read_has_live_rate_and_eta_and_keeps_data(self):
        data = bytes(range(251)) * 700
        self.path.write_bytes(data)
        with patch.object(w, 'BLOCK', 65536):
            result, events = self.capture(w.surface_scan, mode='surface', size=len(data))
        self.assertTrue(result['success'])
        self.assertEqual(result['readable_bytes'], len(data))
        self.assertEqual(result['coverage_percent'], 100)
        self.assertEqual(self.path.read_bytes(), data)
        self.assertTrue(any(e['read_mib_s'] > 0 and e['eta_seconds'] is not None for e in events))

    def test_error_localization_continues_after_failed_region(self):
        size = 3 * 65536 + 512
        self.path.write_bytes(bytes(size))
        real_read = w.os.read
        calls = []
        def faulty(fd, length):
            offset = os.lseek(fd, 0, os.SEEK_CUR)
            calls.append((offset, length))
            if offset <= 70000 < offset + length: raise OSError(errno.EIO, 'simulated media error')
            return real_read(fd, length)
        with patch.object(w, 'BLOCK', 131072), patch.object(w.os, 'read', faulty):
            result, _ = self.capture(w.surface_scan, mode='surface', size=size)
        self.assertFalse(result['success'])
        self.assertEqual(result['bad_ranges'], [dict(offset=65536, length=65536)])
        self.assertEqual(result['bytes_checked'], size)
        self.assertEqual(result['readable_bytes'], size - 65536)
        self.assertEqual(result['unreadable_bytes'], 65536)
        self.assertTrue(any(offset >= 131072 for offset, _ in calls))
        self.assertLess(len(calls), 12)

    def test_transient_error_recovers_and_is_reported(self):
        self.path.write_bytes(bytes(512))
        real_read = w.os.read
        calls = 0
        def faulty(fd, size):
            nonlocal calls
            calls += 1
            if calls == 1: raise OSError(errno.EIO, 'transient')
            return real_read(fd, size)
        with patch.object(w.os, 'read', faulty):
            result, _ = self.capture(w.surface_scan, mode='surface', size=512)
        self.assertTrue(result['success'])
        self.assertEqual(result['retry_count'], 1)
        self.assertEqual(result['errors_found'], 0)

    def test_disconnection_and_eof_abort_instead_of_becoming_bad_regions(self):
        self.path.write_bytes(bytes(512))
        for code in (errno.ENODEV, errno.ENXIO, errno.EACCES):
            with patch.object(w.os, 'read', side_effect=OSError(code, 'fatal')), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OSError):
                w.surface_scan(dict(mode='surface', device=str(self.path), size=512))
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OSError):
            w.surface_scan(dict(mode='surface', device=str(self.path), size=1024))

    def test_bad_region_list_is_bounded_without_losing_counts(self):
        self.path.write_bytes(bytes(512 * 300))
        with patch.object(w, 'BLOCK', 512), patch.object(w.os, 'read', side_effect=OSError(errno.EIO, 'bad')):
            result, _ = self.capture(w.surface_scan, mode='surface', size=512 * 300)
        self.assertEqual(result['errors_found'], 300)
        self.assertEqual(len(result['bad_ranges']), 256)
        self.assertTrue(result['bad_ranges_truncated'])

    def test_sample_plan_is_bounded_aligned_distributed_and_nonoverlapping(self):
        total = 512 * 1024**2
        ranges = w.sample_ranges(total)
        self.assertEqual(len(ranges), 16)
        self.assertEqual(ranges[0][0], 0)
        self.assertEqual(sum(ranges[-1]), total)
        self.assertEqual(sum(length for _, length in ranges), 128 * 1024**2)
        for index, (offset, length) in enumerate(ranges):
            self.assertEqual(offset % 512, 0)
            self.assertLessEqual(offset + length, total)
            if index: self.assertGreaterEqual(offset, sum(ranges[index - 1]))

    def test_sample_report_never_claims_full_scan(self):
        self.path.write_bytes(bytes(4 * 1024**2))
        with patch.object(w, 'sample_ranges', return_value=[(0, 512), (4 * 1024**2 - 512, 512)]):
            result, _ = self.capture(w.surface_scan, mode='sample', size=4 * 1024**2)
        self.assertTrue(result['sampled'])
        self.assertEqual(result['kind'], 'sample')
        self.assertEqual(result['bytes_checked'], 1024)
        self.assertLess(result['coverage_percent'], 1)

    def test_quick_speed_respects_budget_and_device_boundary(self):
        self.path.write_bytes(b'x' * 133)
        start = time.monotonic()
        result, _ = self.capture(w.speed, size=133, speed_profile='quick', seconds=.025)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(self.path.stat().st_size, 133)
        self.assertEqual(len(result['speed_results']), 1)
        row = result['speed_results'][0]
        self.assertEqual(row['block_bytes'], 8 * 1024**2)
        self.assertGreaterEqual(row['write_seconds'], .025)
        self.assertGreaterEqual(row['read_seconds'], .025)
        self.assertGreater(row['write_bytes'], 0)
        self.assertGreater(row['read_bytes'], 0)

    def test_detailed_rows_and_weighted_speed_include_sync(self):
        self.path.write_bytes(bytes(133))
        real_sync = w.os.fsync
        def slow_sync(fd):
            time.sleep(.01)
            real_sync(fd)
        with patch.object(w.os, 'fsync', slow_sync):
            result, events = self.capture(w.speed, size=133, speed_profile='detailed')
        rows = result['speed_results']
        self.assertEqual([r['block_bytes'] for r in rows], [1024**2, 4*1024**2, 16*1024**2])
        self.assertTrue(all(r['write_bytes'] == 133 and r['read_bytes'] == 133 and r['write_seconds'] >= .01 for r in rows))
        self.assertAlmostEqual(result['write_mib_s'], 399 / sum(r['write_seconds'] for r in rows) / 1048576)
        self.assertEqual(sum(e['phase'] == 'synchronizing' for e in events), 3)
        self.assertTrue(all(e['percent'] < 100 for e in events))

    def test_invalid_speed_profile_fails_before_opening_disk(self):
        with self.assertRaises(ValueError): w.speed(dict(device='missing', size=1, speed_profile='invalid'))

if __name__ == '__main__': unittest.main()
