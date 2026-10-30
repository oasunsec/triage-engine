import os
import tempfile
import unittest
from pathlib import Path

from triage_engine.env_loader import load_env_file, load_project_env


class EnvLoaderTests(unittest.TestCase):
    def test_loads_simple_values_without_overwriting_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("# comment\nTEST_TRIAGE_ENV=loaded\nTEST_TRIAGE_QUOTED=\"quoted value\"\n", encoding="utf-8")
            os.environ["TEST_TRIAGE_ENV"] = "existing"
            try:
                self.assertEqual(load_env_file(str(path)), 1)
                self.assertEqual(os.environ["TEST_TRIAGE_ENV"], "existing")
                self.assertEqual(os.environ["TEST_TRIAGE_QUOTED"], "quoted value")
            finally:
                os.environ.pop("TEST_TRIAGE_ENV", None)
                os.environ.pop("TEST_TRIAGE_QUOTED", None)

    def test_project_env_prefers_env_over_env_txt(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text("TEST_TRIAGE_SOURCE=env\n", encoding="utf-8")
            Path(tmp, ".env.txt").write_text("TEST_TRIAGE_SOURCE=txt\nTEST_TRIAGE_SECOND=two\n", encoding="utf-8")
            os.environ.pop("TEST_TRIAGE_SOURCE", None)
            os.environ.pop("TEST_TRIAGE_SECOND", None)
            try:
                self.assertEqual(load_project_env(tmp), 2)
                self.assertEqual(os.environ["TEST_TRIAGE_SOURCE"], "env")
                self.assertEqual(os.environ["TEST_TRIAGE_SECOND"], "two")
            finally:
                os.environ.pop("TEST_TRIAGE_SOURCE", None)
                os.environ.pop("TEST_TRIAGE_SECOND", None)


if __name__ == "__main__":
    unittest.main()
