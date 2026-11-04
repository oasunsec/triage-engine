"""A strict release gate must reject a pilot even when unit validation passes."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('production_readiness', Path(__file__).resolve().parents[1] / 'scripts' / 'production_readiness.py')
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


class ReadinessGateTests(unittest.TestCase):
    def test_validation_collects_function_style_tests_with_pytest(self):
        from types import SimpleNamespace
        with patch.object(readiness.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')) as run:
            result = readiness._run_validation()
        command = run.call_args.args[0]
        self.assertIn('pytest',command)
        self.assertIn('tests/test_packaging_assets.py',command)
        self.assertTrue(result['passed'])

    def test_strict_exit_distinguishes_pilot_from_production_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            for configured, expected in [(False,1),(True,0)]:
                with self.subTest(configured=configured), patch.object(readiness,'_run_validation',return_value={'passed':True}), patch.object(readiness,'_tuning_status',return_value={'configured':configured}), patch.object(readiness,'_sigma_pack_status',return_value={'present':True,'rule_count':4}):
                    report = Path(directory,'nested','readiness.json')
                    self.assertEqual(readiness.main(['--strict','--report',str(report)]),expected)
                    self.assertTrue(report.is_file())

    def test_failed_validation_never_passes(self):
        self.assertEqual(readiness._status_label({'passed':False},{'configured':True},{'present':True,'rule_count':4}),'not_ready')
