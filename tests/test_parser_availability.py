"""Missing parser dependencies must never masquerade as successfully read empty logs."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from parser import evtx_reader


class ParserAvailabilityTests(unittest.TestCase):
    def test_all_unreadable_duplicate_basenames_cannot_produce_a_verdict(self):
        from corrobora.service import InvestigationRequest, run_investigation
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, 'input')
            for host in ['host-a','host-b']:
                folder = root / host
                folder.mkdir(parents=True)
                (folder / 'Security.evtx').write_bytes(b'placeholder')
            case_root = Path(directory, 'cases')
            request = InvestigationRequest(input_source=str(root), case_name='unreadable-duplicates', cases_dir=str(case_root))
            with patch.object(evtx_reader, 'HAS_EVTX', False), patch.object(evtx_reader.shutil, 'which', return_value=None):
                with self.assertRaisesRegex(RuntimeError, 'without producing a verdict'):
                    run_investigation(request)
            self.assertFalse(list(case_root.rglob('report.html')))

    def test_investigation_fails_without_a_verdict_when_every_file_is_unreadable(self):
        from corrobora.service import InvestigationRequest, run_investigation
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'evidence.evtx')
            path.write_bytes(b'placeholder')
            case_root = Path(directory, 'cases')
            request = InvestigationRequest(input_source=str(path), case_name='unreadable', cases_dir=str(case_root))
            with patch.object(evtx_reader, 'HAS_EVTX', False), patch.object(evtx_reader.shutil, 'which', return_value=None):
                with self.assertRaisesRegex(RuntimeError, 'without producing a verdict'):
                    run_investigation(request)
            self.assertFalse(list(case_root.rglob('report.html')))
            self.assertFalse(list(case_root.rglob('findings.json')))

    def test_missing_evtx_dependency_raises_actionable_error(self):
        with patch.object(evtx_reader, 'HAS_EVTX', False), patch.object(evtx_reader.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'EVTX parser unavailable'):
                evtx_reader.read_evtx('unavailable.evtx')

    def test_missing_dependency_is_reported_as_file_error_not_file_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'evidence.evtx')
            path.write_bytes(b'placeholder')
            progress = []
            with patch.object(evtx_reader, 'HAS_EVTX', False), patch.object(evtx_reader.shutil, 'which', return_value=None):
                self.assertEqual(evtx_reader.read_evtx_path(str(path), progress_callback=progress.append), [])
            errors = [item for item in progress if item.get('status') == 'file_error']
            self.assertEqual(len(errors),1)
            self.assertIn('EVTX parser unavailable',str(errors[0]))
            self.assertFalse(any(item.get('status') == 'file_complete' for item in progress))
