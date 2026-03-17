import json, shutil, tempfile, unittest
from pathlib import Path
from tests.test_regressions import ROOT
from triage_engine.cli import main as cli_main
SAMPLE_CACHE_DIR = ROOT / "sample_cache"
SAMPLES = []
SAMPLES.append(("hayabusa_mshta.evtx", "MSHTA HTA Execution"))
SAMPLES.append(("hayabusa_regsvr32_sct.evtx", "Regsvr32 Scriptlet Execution"))
SAMPLES.append(("hayabusa_rundll32_openurl.evtx", "Rundll32 Proxy Execution"))
SAMPLES.append(("hayabusa_wmic_xsl.evtx", "WMIC XSL Script Processing"))
SAMPLES.append(("mitre_certutil_download.evtx", "Certutil Remote Download"))
SAMPLES.append(("mitre_bits_transfer.evtx", "BITSAdmin Transfer"))
SAMPLES.append(("mitre_bits_powershell.evtx", "PowerShell BITS Download"))
SAMPLES.append(("hayabusa_bits_notify.evtx", "BITS Notify Command Execution"))
SAMPLES.append(("hayabusa_bits_client.evtx", "BITS Client Suspicious Job"))
SAMPLES.append(("hayabusa_dcom_mshta.evtx", "DCOM MSHTA Remote Execution"))
SAMPLES.append(("hayabusa_remote_registry_wmi.evtx", "WMI Remote Registry Modification"))
SAMPLES.append(("mitre_printnightmare_cmd.evtx", "Print Spooler Exploitation"))
SAMPLES.append(("mitre_user_rights.evtx", "Sensitive User Right Assigned"))
SAMPLES.append(("mitre_system_rights.evtx", "System Security Access Granted"))
SAMPLES.append(("mitre_sid_history.evtx", "SID History Added"))
SAMPLES.append(("hayabusa_dcsync_4662.evtx", "DCSync Directory Replication"))
SAMPLES.append(("hayabusa_new_user_security.evtx", "New Privileged Account Provisioned"))
SAMPLES.append(("mitre_user_added_local_admin.evtx", "Member Added to Sensitive Group"))
SAMPLES.append(("evtx_fake_computer_4720.evtx", "Fake Computer Account Created"))
SAMPLES.append(("mitre_fake_computer_created.evtx", "Fake Computer Account Created"))
SAMPLES.append(("evtx_guest_rid_hijack.evtx", "Guest RID Hijack"))
SAMPLES.append(("mitre_fast_user_create_delete.evtx", "Rapid User Create/Delete"))
class T(unittest.TestCase):
    def _run(self, source, case_name):
        d = tempfile.mkdtemp(prefix="triage-lolbin-smoke-", dir=str(ROOT))
        self.addCleanup(shutil.rmtree, d, True)
        self.assertEqual(cli_main(["investigate","--evtx",str(source),"--case",case_name,"--cases-dir",d]), 0)
        return json.loads((Path(d) / case_name / "findings.json").read_text(encoding="utf-8"))
    def test_samples(self):
        for stem, title in SAMPLES:
            with self.subTest(sample=stem):
                s = SAMPLE_CACHE_DIR / stem
                if not s.is_file(): self.skipTest(f"{stem} not available")
                f = self._run(s, f"test-{s.stem}")
                self.assertTrue(any(i.get("title") == title for i in f["findings"]))
if __name__ == "__main__": unittest.main()
