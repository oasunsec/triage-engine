import unittest
from detectors import persistence
from tests.test_regressions import make_event
class T(unittest.TestCase):
    def test_bits_notify_unit(self):
        p=make_event(1,computer="WIN7",channel="Microsoft-Windows-Sysmon/Operational",provider="Microsoft-Windows-Sysmon",process_name_value=r"C:\Windows\System32\mobsync.exe",command_line_value=r"C:\Windows\System32\mobsync.exe -Embedding")
        c=make_event(1,computer="WIN7",channel="Microsoft-Windows-Sysmon/Operational",provider="Microsoft-Windows-Sysmon",process_name_value=r"C:\Windows\System32\regsvr32.exe")
        self.assertTrue(any(a.rule_name=="BITS Notify Command Execution" for a in persistence.detect([p,c])))
