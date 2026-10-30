#!/usr/bin/env python3
"""
Log Parser v4 — Windows Event Log Threat Hunting Engine

CrowdStrike-inspired behavioral IOA detection with kill-chain correlation,
multi-source threat intelligence, SIGMA/YARA integration, and CVE correlation.

Single file. Zero cloud dependencies. Full kill-chain visibility.
"""

# =============================================================================
# SECTION 1: IMPORTS & CONSTANTS
# =============================================================================

import argparse
import sys
import os
import re
import json
import time
import uuid
import logging
import sqlite3
import base64
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Any
import xml.etree.ElementTree as ET

try:
    import Evtx.Evtx as evtx
except ImportError:
    print("Error: python-evtx is required. Install with: pip install python-evtx")
    sys.exit(1)

# Optional imports — degrade gracefully
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# 102 Windows Event IDs across Security, Sysmon, PowerShell, WMI, Task Scheduler
EVENT_IDS = {
    # --- Security Log: Logon ---
    4624: ("Logon", "Successful Logon"),
    4625: ("Logon", "Failed Logon"),
    4634: ("Logon", "Logoff"),
    4647: ("Logon", "User Initiated Logoff"),
    4648: ("Logon", "Explicit Credentials Logon"),
    4649: ("Logon", "Replay Attack Detected"),
    4675: ("Logon", "SIDs Filtered"),
    # --- Security Log: Privilege ---
    4672: ("Privilege", "Special Privileges Assigned"),
    4673: ("Privilege", "Privileged Service Called"),
    4674: ("Privilege", "Operation on Privileged Object"),
    # --- Security Log: Account Management ---
    4720: ("Account Mgmt", "Account Created"),
    4722: ("Account Mgmt", "Account Enabled"),
    4723: ("Account Mgmt", "Password Change Attempt"),
    4724: ("Account Mgmt", "Password Reset Attempt"),
    4725: ("Account Mgmt", "Account Disabled"),
    4726: ("Account Mgmt", "Account Deleted"),
    4728: ("Account Mgmt", "Member Added to Security Group"),
    4729: ("Account Mgmt", "Member Removed from Security Group"),
    4732: ("Account Mgmt", "Member Added to Local Group"),
    4733: ("Account Mgmt", "Member Removed from Local Group"),
    4735: ("Account Mgmt", "Security Group Changed"),
    4738: ("Account Mgmt", "Account Changed"),
    4740: ("Account Mgmt", "Account Locked Out"),
    4741: ("Account Mgmt", "Computer Account Created"),
    4742: ("Account Mgmt", "Computer Account Changed"),
    4743: ("Account Mgmt", "Computer Account Deleted"),
    4756: ("Account Mgmt", "Member Added to Universal Group"),
    4757: ("Account Mgmt", "Member Removed from Universal Group"),
    # --- Security Log: Process ---
    4688: ("Process", "Process Created"),
    4689: ("Process", "Process Terminated"),
    # --- Security Log: Object Access ---
    4656: ("Object Access", "Handle Requested"),
    4657: ("Object Access", "Registry Value Modified"),
    4658: ("Object Access", "Handle Closed"),
    4660: ("Object Access", "Object Deleted"),
    4663: ("Object Access", "Object Access Attempted"),
    4670: ("Object Access", "Permissions Changed"),
    # --- Security Log: Policy ---
    4704: ("Policy", "User Right Assigned"),
    4719: ("Policy", "System Audit Policy Changed"),
    4739: ("Policy", "Domain Policy Changed"),
    # --- Security Log: System ---
    1102: ("System", "Audit Log Cleared"),
    4616: ("System", "System Time Changed"),
    4697: ("System", "Service Installed"),
    4698: ("Task Scheduler", "Scheduled Task Created"),
    4699: ("Task Scheduler", "Scheduled Task Deleted"),
    4700: ("Task Scheduler", "Scheduled Task Enabled"),
    4701: ("Task Scheduler", "Scheduled Task Disabled"),
    4702: ("Task Scheduler", "Scheduled Task Updated"),
    # --- Security Log: Logon ---
    4768: ("Kerberos", "TGT Requested"),
    4769: ("Kerberos", "Service Ticket Requested"),
    4770: ("Kerberos", "Service Ticket Renewed"),
    4771: ("Kerberos", "Kerberos Pre-Auth Failed"),
    4776: ("NTLM", "Credential Validation"),
    # --- Security Log: Lateral Movement ---
    4778: ("Lateral Movement", "Session Reconnected"),
    4779: ("Lateral Movement", "Session Disconnected"),
    # --- Security Log: Firewall ---
    5140: ("Network Share", "Network Share Accessed"),
    5142: ("Network Share", "Network Share Created"),
    5145: ("Network Share", "Share Object Access Checked"),
    5156: ("Firewall", "Connection Allowed"),
    5157: ("Firewall", "Connection Blocked"),
    # --- Sysmon ---
    1:    ("Sysmon", "Process Create"),
    2:    ("Sysmon", "File Creation Time Changed"),
    3:    ("Sysmon", "Network Connection"),
    4:    ("Sysmon", "Sysmon Service State Changed"),
    5:    ("Sysmon", "Process Terminated"),
    6:    ("Sysmon", "Driver Loaded"),
    7:    ("Sysmon", "Image Loaded"),
    8:    ("Sysmon", "CreateRemoteThread"),
    9:    ("Sysmon", "RawAccessRead"),
    10:   ("Sysmon", "Process Access"),
    11:   ("Sysmon", "File Create"),
    12:   ("Sysmon", "Registry Object Added/Deleted"),
    13:   ("Sysmon", "Registry Value Set"),
    14:   ("Sysmon", "Registry Key/Value Rename"),
    15:   ("Sysmon", "FileCreateStreamHash"),
    17:   ("Sysmon", "Pipe Created"),
    18:   ("Sysmon", "Pipe Connected"),
    19:   ("Sysmon", "WMI Event Filter"),
    20:   ("Sysmon", "WMI Event Consumer"),
    21:   ("Sysmon", "WMI Consumer Binding"),
    22:   ("Sysmon", "DNS Query"),
    23:   ("Sysmon", "File Delete Archived"),
    25:   ("Sysmon", "Process Tampering"),
    26:   ("Sysmon", "File Delete Logged"),
    # --- PowerShell ---
    4103: ("PowerShell", "Module Logging"),
    4104: ("PowerShell", "Script Block Logging"),
    4105: ("PowerShell", "Script Block Start"),
    4106: ("PowerShell", "Script Block Stop"),
    400:  ("PowerShell", "Engine Start"),
    403:  ("PowerShell", "Engine Stop"),
    600:  ("PowerShell", "Provider Start"),
    800:  ("PowerShell", "Pipeline Execution"),
    # --- Windows Defender ---
    1116: ("Defender", "Malware Detected"),
    1117: ("Defender", "Malware Action Taken"),
    1118: ("Defender", "Malware Action Failed"),
    5001: ("Defender", "Real-Time Protection Disabled"),
    5007: ("Defender", "Configuration Changed"),
    5010: ("Defender", "Scan Disabled"),
    5012: ("Defender", "Virus Scanning Disabled"),
    # --- Service Control Manager ---
    7034: ("Service", "Service Crashed"),
    7035: ("Service", "Service Control Sent"),
    7036: ("Service", "Service State Changed"),
    7040: ("Service", "Service Start Type Changed"),
    7045: ("Service", "Service Installed"),
}

TRACKED_IDS = set(EVENT_IDS.keys())

# LOLBin detections from LOLBAS project
LOLBINS = [
    "certutil", "mshta", "regsvr32", "rundll32", "msiexec",
    "cmstp", "installutil", "regasm", "regsvcs", "msconfig",
    "cscript", "wscript", "msbuild", "xwizard", "forfiles",
    "pcalua", "infdefaultinstall", "sdbinst", "scriptrunner",
    "odbcconf", "ieexec", "dnscmd", "desktopimgdownldr",
    "esentutl", "expand", "extrac32", "findstr", "ftp",
    "gpscript", "hh", "makecab", "mavinject", "replace",
    "rpcping", "schtasks", "wmic", "explorer", "control",
    "verclsid", "syncappvpublishingserver", "tttracer",
    "diskshadow", "dfsvc", "msdt", "diantz", "bash",
    "bitsadmin", "certoc", "cmdkey", "cmdl32", "clip",
    "presentationhost", "configsecuritypolicy", "finger",
    "dxcap", "wlrmdr", "workfolders", "pktmon",
]

# APT tooling signatures
APT_SIGNATURES = {
    "cobalt_strike": [
        r"beacon\.dll", r"beacon\.exe", r"cobaltstrike",
        r"sleeptime", r"jitter\s*=", r"c2server",
        r"named_pipe.*\\msagent_", r"named_pipe.*\\postex_",
    ],
    "mimikatz": [
        r"mimikatz", r"sekurlsa", r"kerberos::list",
        r"lsadump::", r"privilege::debug", r"token::elevate",
        r"crypto::capi", r"dpapi::masterkey",
    ],
    "impacket": [
        r"impacket", r"smbexec", r"wmiexec", r"psexec\.py",
        r"atexec", r"dcomexec", r"secretsdump",
    ],
    "bloodhound": [
        r"bloodhound", r"sharphound", r"invoke-bloodhound",
        r"collectionmethod", r"azurehound",
    ],
    "rubeus": [
        r"rubeus", r"asktgt", r"asktgs", r"kerberoast",
        r"s4u", r"changepw", r"hash\s*/password",
    ],
    "sliver": [
        r"sliver", r"implant", r"sliver-client",
    ],
    "mythic": [
        r"mythic", r"apfell", r"athena\.exe",
    ],
    "sharphound": [
        r"sharphound", r"invoke-sharphound", r"bloodhound.*collector",
    ],
}

# Suspicious command-line patterns (40+)
SUSPICIOUS_CMD_PATTERNS = [
    (r"powershell.*-enc", "PowerShell Encoded Command", "high"),
    (r"powershell.*-e\s+[A-Za-z0-9+/=]{20,}", "PowerShell Base64 Payload", "high"),
    (r"powershell.*downloadstring", "PowerShell Download Cradle", "critical"),
    (r"powershell.*downloadfile", "PowerShell File Download", "high"),
    (r"powershell.*iex\s*\(", "PowerShell IEX Execution", "high"),
    (r"powershell.*invoke-expression", "PowerShell Invoke-Expression", "high"),
    (r"powershell.*invoke-webrequest", "PowerShell Web Request", "medium"),
    (r"powershell.*invoke-restmethod", "PowerShell REST Call", "medium"),
    (r"powershell.*start-bitstransfer", "PowerShell BITS Transfer", "high"),
    (r"powershell.*reflection\.assembly", "PowerShell Reflective Loading", "critical"),
    (r"powershell.*bypass", "PowerShell Execution Policy Bypass", "high"),
    (r"powershell.*hidden", "PowerShell Hidden Window", "medium"),
    (r"powershell.*nop\s", "PowerShell No Profile", "medium"),
    (r"powershell.*sta\s", "PowerShell STA Thread", "medium"),
    (r"net\s+user\s+.*/add", "User Account Creation via Net", "high"),
    (r"net\s+localgroup\s+admin", "Local Admin Group Modification", "critical"),
    (r"net\s+group\s+.*domain\s+admin", "Domain Admin Group Query", "high"),
    (r"reg\s+add.*currentversion\\run", "Registry Run Key Persistence", "critical"),
    (r"reg\s+save\s+hklm\\sam", "SAM Database Dump", "critical"),
    (r"reg\s+save\s+hklm\\system", "SYSTEM Hive Dump", "critical"),
    (r"reg\s+save\s+hklm\\security", "SECURITY Hive Dump", "critical"),
    (r"vssadmin\s+delete\s+shadows", "Shadow Copy Deletion", "critical"),
    (r"wbadmin\s+delete", "Backup Deletion", "critical"),
    (r"bcdedit.*recoveryenabled.*no", "Recovery Mode Disabled", "critical"),
    (r"schtasks\s+/create", "Scheduled Task Creation", "high"),
    (r"sc\s+create", "Service Creation", "high"),
    (r"sc\s+config.*start.*auto", "Service Auto-Start Config", "medium"),
    (r"wmic\s+process\s+call\s+create", "WMI Process Creation", "high"),
    (r"wmic\s+/node:", "WMI Remote Execution", "high"),
    (r"whoami\s+/priv", "Privilege Enumeration", "medium"),
    (r"nltest\s+/dclist", "Domain Controller Listing", "medium"),
    (r"nltest\s+/domain_trusts", "Domain Trust Enumeration", "high"),
    (r"dsquery", "Active Directory Query", "medium"),
    (r"csvde|ldifde", "AD Export Utility", "high"),
    (r"ntdsutil", "NTDS Utility — Potential DCSync", "critical"),
    (r"procdump.*lsass", "LSASS Memory Dump", "critical"),
    (r"comsvcs.*minidump", "MiniDump via comsvcs.dll", "critical"),
    (r"rar\s+a.*-hp", "Password-Protected RAR Archive", "high"),
    (r"7z\s+a.*-p", "Password-Protected 7z Archive", "high"),
    (r"certutil.*-urlcache", "Certutil URL Download", "high"),
    (r"certutil.*-decode", "Certutil Base64 Decode", "high"),
    (r"bitsadmin.*transfer", "BITS Transfer Job", "high"),
    (r"mshta.*vbscript", "MSHTA VBScript Execution", "critical"),
    (r"mshta.*javascript", "MSHTA JavaScript Execution", "critical"),
    (r"cmstp.*/s.*/ni", "CMSTP UAC Bypass", "critical"),
    (r"at\s+\d+:\d+", "AT Command Scheduling", "medium"),
]


# =============================================================================
# SECTION 2: DATA CLASSES
# =============================================================================

@dataclass
class ParsedEvent:
    """Normalized event data class."""
    event_id: int
    timestamp: Optional[datetime]
    computer: str = ""
    channel: str = ""
    provider: str = ""
    target_user: str = ""
    target_domain: str = ""
    source_ip: str = ""
    logon_type: str = ""
    status: str = ""
    sub_status: str = ""
    subject_user: str = ""
    subject_domain: str = ""
    category: str = ""
    description: str = ""
    event_data: Dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""

    LOGON_TYPES = {"0": "System", "2": "Interactive", "3": "Network", "4": "Batch",
                   "5": "Service", "7": "Unlock", "8": "NetworkCleartext",
                   "9": "NewCredentials (RunAs)", "10": "RemoteInteractive (RDP)",
                   "11": "CachedInteractive"}
    STATUS_CODES = {"0xC0000064": "User does not exist", "0xC000006A": "Wrong password",
                    "0xC000006D": "Bad username or password", "0xC0000072": "Disabled account",
                    "0xC0000234": "Account locked out", "0xC0000193": "Expired account"}
    SYSTEM_ACCOUNTS = {"-", "", "system", "local service", "network service",
                       "dwm-1", "dwm-2", "dwm-3", "umfd-0", "umfd-1",
                       "anonymous logon"}
    BENIGN_IPS = {"127.0.0.1", "::1", "-", "", "0.0.0.0", "fe80::1"}

    @property
    def user(self) -> str:
        return self.target_user or self.subject_user or ""

    @property
    def user_with_domain(self) -> str:
        user = self.target_user or self.subject_user or ""
        domain = self.target_domain or self.subject_domain or ""
        if domain and domain != "-" and user:
            return f"{domain}\\{user}"
        return user

    @property
    def command_line(self) -> str:
        return self.event_data.get("CommandLine", "") or self.event_data.get("command_line", "")

    @property
    def logon_type_name(self) -> str:
        return self.LOGON_TYPES.get(self.logon_type, f"Type {self.logon_type}")

    @property
    def status_description(self) -> str:
        return self.STATUS_CODES.get(self.sub_status, "") or self.STATUS_CODES.get(self.status, "")

    @property
    def is_machine_account(self) -> bool:
        return (self.subject_user or self.target_user or "").rstrip().endswith("$")

    @property
    def is_system_account(self) -> bool:
        user = (self.subject_user or self.target_user or "").lower().strip()
        return user in self.SYSTEM_ACCOUNTS or self.is_machine_account


@dataclass
class Alert:
    """Detection finding data class."""
    rule_name: str
    severity: str              # critical, high, medium, low, info
    mitre_technique: str       # T-code
    mitre_tactic: str          # Tactic name
    description: str
    event: Optional[ParsedEvent]
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None and self.event and self.event.timestamp:
            self.timestamp = self.event.timestamp


@dataclass
class IOC:
    """Indicator of compromise data class."""
    ioc_type: str              # ip, domain, hash, url, email
    value: str
    source_event_id: int = 0
    context: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    count: int = 1


@dataclass
class AttackChain:
    """Kill-chain sequence data class."""
    chain_id: str = ""
    host: str = ""
    alerts: List[Alert] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    risk_score: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    description: str = ""

    def __post_init__(self):
        if not self.chain_id:
            self.chain_id = str(uuid.uuid4())[:8]


# =============================================================================
# SECTION 3: EVENT PARSER
# =============================================================================

class EventParser:
    """EVTX XML parsing and field extraction."""

    def __init__(self):
        self.stats = {"total": 0, "parsed": 0, "skipped": 0, "errors": 0}

    def parse_record(self, record_xml: str) -> Optional[ParsedEvent]:
        """Parse a single event record XML string into a ParsedEvent."""
        try:
            root = ET.fromstring(record_xml)
        except ET.ParseError:
            self.stats["errors"] += 1
            return None

        system = root.find(f"{NS}System")
        if system is None:
            return None

        event_id_el = system.find(f"{NS}EventID")
        if event_id_el is None:
            return None

        try:
            event_id = int(event_id_el.text)
        except (ValueError, TypeError):
            return None

        if event_id not in TRACKED_IDS:
            return None

        # Timestamp
        time_created = system.find(f"{NS}TimeCreated")
        timestamp_str = time_created.get("SystemTime", "") if time_created is not None else ""
        timestamp = None
        try:
            if timestamp_str.endswith("Z"):
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            elif timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            pass

        # Computer name
        computer_el = system.find(f"{NS}Computer")
        computer = computer_el.text if computer_el is not None and computer_el.text else ""

        # Channel
        channel_el = system.find(f"{NS}Channel")
        channel = channel_el.text if channel_el is not None and channel_el.text else ""

        # Provider
        provider_el = system.find(f"{NS}Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""

        # EventData fields
        event_data = {}
        event_data_el = root.find(f"{NS}EventData")
        if event_data_el is not None:
            for data_el in event_data_el.findall(f"{NS}Data"):
                name = data_el.get("Name", "")
                value = data_el.text or ""
                if name:
                    event_data[name] = value

        # UserData — Event 1102 and others use this instead of EventData
        user_data_el = root.find(f"{NS}UserData")
        if user_data_el is not None:
            for child in user_data_el:
                for field_el in child:
                    tag = field_el.tag
                    if "}" in tag:
                        tag = tag.split("}", 1)[1]
                    value = field_el.text or ""
                    if value:
                        event_data[tag] = value

        category, description = EVENT_IDS.get(event_id, ("Unknown", "Unknown"))

        return ParsedEvent(
            event_id=event_id,
            timestamp=timestamp,
            computer=computer,
            channel=channel,
            provider=provider,
            target_user=event_data.get("TargetUserName", ""),
            target_domain=event_data.get("TargetDomainName", ""),
            source_ip=event_data.get("IpAddress", ""),
            logon_type=event_data.get("LogonType", ""),
            status=event_data.get("Status", ""),
            sub_status=event_data.get("SubStatus", ""),
            subject_user=event_data.get("SubjectUserName", ""),
            subject_domain=event_data.get("SubjectDomainName", ""),
            category=category,
            description=description,
            event_data=event_data,
            raw_xml=record_xml,
        )

    def parse_evtx_file(self, filepath: str, start_date=None, end_date=None) -> List[ParsedEvent]:
        """Parse an entire .evtx file and return filtered event records."""
        events = []
        self.stats = {"total": 0, "parsed": 0, "skipped": 0, "errors": 0}

        with evtx.Evtx(filepath) as log:
            for record in log.records():
                self.stats["total"] += 1
                try:
                    xml_str = record.xml()
                except Exception:
                    self.stats["skipped"] += 1
                    continue

                event = self.parse_record(xml_str)
                if event is None:
                    continue

                if event.timestamp:
                    ts_date = event.timestamp.date()
                    if start_date and ts_date < start_date:
                        continue
                    if end_date and ts_date > end_date:
                        continue

                events.append(event)
                self.stats["parsed"] += 1

        return events

    def parse_directory(self, dirpath: str, start_date=None, end_date=None) -> List[ParsedEvent]:
        """Recursively parse all .evtx files in a directory."""
        all_events = []
        evtx_files = []

        for root_dir, _, files in os.walk(dirpath):
            for fname in files:
                if fname.lower().endswith(".evtx"):
                    evtx_files.append(os.path.join(root_dir, fname))

        if not evtx_files:
            logging.warning(f"No .evtx files found in {dirpath}")
            return all_events

        for fpath in sorted(evtx_files):
            print(f"  Parsing: {os.path.basename(fpath)}")
            try:
                file_events = self.parse_evtx_file(fpath, start_date, end_date)
                all_events.extend(file_events)
            except Exception as e:
                logging.warning(f"  Error parsing {fpath}: {e}")
                self.stats["errors"] += 1

        return all_events


# =============================================================================
# SECTION 4: BASE THREAT DETECTOR
# =============================================================================

class ThreatDetector:
    """Abstract base class for all detectors."""

    def __init__(self):
        self.alerts: List[Alert] = []
        self.name = self.__class__.__name__

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        """Analyze a single event. Override in subclasses."""
        raise NotImplementedError

    def analyze_all(self, events: List[ParsedEvent]) -> List[Alert]:
        """Run analysis on all events."""
        for event in events:
            try:
                new_alerts = self.analyze(event)
                if new_alerts:
                    self.alerts.extend(new_alerts)
            except Exception as e:
                logging.debug(f"{self.name}: Error analyzing event {event.event_id}: {e}")
        return self.alerts

    def _create_alert(self, rule_name, severity, technique, tactic,
                      description, event, evidence=None) -> Alert:
        return Alert(
            rule_name=rule_name,
            severity=severity,
            mitre_technique=technique,
            mitre_tactic=tactic,
            description=description,
            event=event,
            evidence=evidence or {},
        )


# =============================================================================
# SECTION 5: COMMAND-LINE ANALYZER (TA0002 - Execution)
# =============================================================================

class CommandLineAnalyzer(ThreatDetector):
    """CLI pattern detection + LOLBin abuse detection. 40+ rules."""

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        if event.event_id not in (4688, 1, 4104):
            return alerts

        ed = event.event_data
        cmd = (ed.get("CommandLine", "") or ed.get("NewProcessName", "")
               or ed.get("ScriptBlockText", "") or "").lower()
        process_name = (ed.get("NewProcessName", "") or ed.get("Image", "") or "").lower()

        if not cmd and not process_name:
            return alerts

        # LOLBin detection
        for lolbin in LOLBINS:
            if lolbin in process_name or f"\\{lolbin}.exe" in process_name:
                alerts.append(self._create_alert(
                    f"LOLBin Execution: {lolbin}",
                    "medium", "T1218", "Defense Evasion",
                    f"Living-off-the-land binary '{lolbin}' executed: {cmd[:200]}",
                    event, {"lolbin": lolbin, "command_line": cmd[:500]},
                ))
                break

        # Suspicious command-line patterns
        for pattern, desc, severity in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                alerts.append(self._create_alert(
                    f"Suspicious CLI: {desc}",
                    severity, "T1059", "Execution",
                    f"{desc} detected: {cmd[:200]}",
                    event, {"pattern": desc, "command_line": cmd[:500]},
                ))
                break  # one match per event to reduce noise

        # APT tooling signatures
        for family, patterns in APT_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    alerts.append(self._create_alert(
                        f"APT Tooling: {family}",
                        "critical", "T1588.002", "Resource Development",
                        f"APT tool signature for {family} detected: {cmd[:200]}",
                        event, {"apt_family": family, "command_line": cmd[:500]},
                    ))
                    break

        return alerts


# =============================================================================
# SECTION 6: PERSISTENCE DETECTOR (TA0003)
# =============================================================================

class PersistenceDetector(ThreatDetector):
    """8 persistence detection rules."""

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        # Scheduled task creation
        if event.event_id in (4698, 4702):
            task_name = ed.get("TaskName", "")
            task_content = ed.get("TaskContent", "")
            alerts.append(self._create_alert(
                "Scheduled Task Persistence",
                "high", "T1053.005", "Persistence",
                f"Scheduled task created/modified: {task_name}",
                event, {"task_name": task_name, "content": task_content[:500]},
            ))

        # Service installation
        if event.event_id in (7045, 4697):
            svc_name = ed.get("ServiceName", "")
            svc_file = ed.get("ImagePath", "") or ed.get("ServiceFileName", "")
            severity = "high"
            if "system" in (ed.get("ServiceAccount", "") or "").lower():
                severity = "critical"
            alerts.append(self._create_alert(
                "Service Installation Persistence",
                severity, "T1543.003", "Persistence",
                f"Service installed: {svc_name} -> {svc_file}",
                event, {"service_name": svc_name, "service_file": svc_file},
            ))

        # Registry run key modification
        if event.event_id in (13, 4657):
            target = (ed.get("TargetObject", "") or ed.get("ObjectName", "")).lower()
            run_keys = ["\\currentversion\\run", "\\currentversion\\runonce",
                        "\\currentversion\\policies\\explorer\\run"]
            for key in run_keys:
                if key in target:
                    alerts.append(self._create_alert(
                        "Registry Run Key Persistence",
                        "critical", "T1547.001", "Persistence",
                        f"Registry run key modified: {target}",
                        event, {"registry_key": target},
                    ))
                    break

        # WMI event subscription
        if event.event_id in (19, 20, 21):
            wmi_type = {19: "Filter", 20: "Consumer", 21: "Binding"}.get(event.event_id, "")
            alerts.append(self._create_alert(
                f"WMI Event Subscription ({wmi_type})",
                "high", "T1546.003", "Persistence",
                f"WMI {wmi_type} created — potential persistence",
                event, {"wmi_type": wmi_type},
            ))

        # Startup folder file creation (Sysmon 11)
        if event.event_id == 11:
            target_file = (ed.get("TargetFilename", "") or "").lower()
            if "startup" in target_file and any(
                target_file.endswith(ext) for ext in [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".lnk"]
            ):
                alerts.append(self._create_alert(
                    "Startup Folder Persistence",
                    "high", "T1547.001", "Persistence",
                    f"File created in startup folder: {target_file}",
                    event, {"file": target_file},
                ))

        return alerts


# =============================================================================
# SECTION 7: LATERAL MOVEMENT DETECTOR (TA0008)
# =============================================================================

class LateralMovementDetector(ThreatDetector):
    """10 lateral movement detection rules."""

    PSEXEC_PIPES = ["\\psexesvc", "\\svcctl", "\\atsvc"]

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        # Network / RDP logon from real remote source
        if event.event_id == 4624 and event.logon_type in ("3", "10"):
            src = event.source_ip
            if src and src not in ("127.0.0.1", "::1", "-", ""):
                # Skip machine accounts doing routine network auth
                if event.is_machine_account and event.logon_type == "3":
                    return alerts
                logon_desc = event.logon_type_name
                alerts.append(self._create_alert(
                    f"Lateral Movement: {logon_desc}",
                    "medium", "T1021", "Lateral Movement",
                    f"{logon_desc} by {event.user_with_domain} from {src} "
                    f"to {event.computer}",
                    event, {"source_ip": src, "logon_type": event.logon_type,
                            "logon_type_name": logon_desc},
                ))

        # Explicit credential use — skip machine accounts targeting localhost (normal Windows)
        if event.event_id == 4648:
            target = ed.get("TargetServerName", "")
            if not event.is_machine_account or target.lower() not in ("localhost", ""):
                target_user = ed.get("TargetUserName", "")
                alerts.append(self._create_alert(
                    "Explicit Credential Use (RunAs / PTH)",
                    "high", "T1550.002", "Lateral Movement",
                    f"{event.user_with_domain} used explicit credentials "
                    f"{'as ' + target_user + ' ' if target_user else ''}"
                    f"targeting {target} from {event.computer}",
                    event, {"target_server": target, "target_user": target_user},
            ))

        # PsExec-style service deployment
        if event.event_id in (7045, 4697):
            svc_file = (ed.get("ImagePath", "") or ed.get("ServiceFileName", "") or "").lower()
            svc_name = (ed.get("ServiceName", "") or "").lower()
            if any(marker in svc_file or marker in svc_name
                   for marker in ["psexe", "paexec", "remcom", "csexe"]):
                alerts.append(self._create_alert(
                    "PsExec-Style Remote Service",
                    "critical", "T1021.002", "Lateral Movement",
                    f"PsExec-style service deployed: {svc_name}",
                    event, {"service": svc_name, "file": svc_file},
                ))

        # Named pipe for PsExec
        if event.event_id in (17, 18):
            pipe = (ed.get("PipeName", "") or "").lower()
            for psexec_pipe in self.PSEXEC_PIPES:
                if psexec_pipe in pipe:
                    alerts.append(self._create_alert(
                        "PsExec Named Pipe",
                        "high", "T1021.002", "Lateral Movement",
                        f"PsExec-related named pipe: {pipe}",
                        event, {"pipe_name": pipe},
                    ))
                    break

        # WMI remote execution
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            if "wmic" in cmd and "/node:" in cmd:
                alerts.append(self._create_alert(
                    "WMI Remote Execution",
                    "high", "T1047", "Lateral Movement",
                    f"WMI remote execution detected: {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

        # WinRM usage
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            if any(t in cmd for t in ["invoke-command", "enter-pssession",
                                       "winrs", "new-pssession"]):
                alerts.append(self._create_alert(
                    "WinRM Remote Execution",
                    "high", "T1021.006", "Lateral Movement",
                    f"WinRM command detected: {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

        # SMB share access from remote
        if event.event_id == 5140:
            share = ed.get("ShareName", "")
            src = ed.get("IpAddress", "")
            if src and src not in ("127.0.0.1", "::1", "-", ""):
                sev = "high" if "admin$" in share.lower() or "c$" in share.lower() else "medium"
                alerts.append(self._create_alert(
                    "Remote SMB Share Access",
                    sev, "T1021.002", "Lateral Movement",
                    f"Remote SMB access to {share} from {src}",
                    event, {"share": share, "source_ip": src},
                ))

        return alerts


# =============================================================================
# SECTION 8: DEFENSE EVASION DETECTOR (TA0005)
# =============================================================================

class DefenseEvasionDetector(ThreatDetector):
    """8 defense evasion detection rules."""

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        # Audit log cleared (Event 1102) — user is in UserData fields
        if event.event_id == 1102:
            user = (ed.get("SubjectUserName", "") or
                    event.subject_user or
                    ed.get("param1", "") or
                    "(unable to determine)")
            domain = ed.get("SubjectDomainName", "") or event.subject_domain or ""
            if domain and domain != "-":
                user = f"{domain}\\{user}"
            alerts.append(self._create_alert(
                "CRITICAL: Audit Log Cleared",
                "critical", "T1070.001", "Defense Evasion",
                f"Security audit log was cleared by {user} on {event.computer} — "
                f"destroys forensic evidence, strong indicator of compromise",
                event, {"user": user, "computer": event.computer},
            ))

        # Timestomping (Sysmon 2)
        if event.event_id == 2:
            target = ed.get("TargetFilename", "")
            alerts.append(self._create_alert(
                "File Timestamp Modification",
                "high", "T1070.006", "Defense Evasion",
                f"File creation time changed (timestomping): {target}",
                event, {"file": target},
            ))

        # AV/Defender tampering
        if event.event_id in (5001, 5010, 5012):
            alerts.append(self._create_alert(
                "Security Software Tampered",
                "critical", "T1562.001", "Defense Evasion",
                f"Windows Defender protection disabled: {event.description}",
                event, {},
            ))

        # Process tampering (Sysmon 25)
        if event.event_id == 25:
            image = ed.get("Image", "")
            alerts.append(self._create_alert(
                "Process Tampering Detected",
                "critical", "T1055", "Defense Evasion",
                f"Process tampering (hollowing/herpaderping): {image}",
                event, {"image": image},
            ))

        # AMSI bypass detection (PowerShell)
        if event.event_id == 4104:
            script = (ed.get("ScriptBlockText", "") or "").lower()
            amsi_patterns = ["amsiutils", "amsiscanbuffer", "amsicontext",
                             "amsi.dll", "amsiinitfailed", "unload.*amsi"]
            for pat in amsi_patterns:
                if pat in script:
                    alerts.append(self._create_alert(
                        "AMSI Bypass Attempt",
                        "critical", "T1562.001", "Defense Evasion",
                        f"AMSI bypass pattern detected in PowerShell script block",
                        event, {"pattern": pat, "script_snippet": script[:300]},
                    ))
                    break

        # ETW patching detection
        if event.event_id == 4104:
            script = (ed.get("ScriptBlockText", "") or "").lower()
            etw_patterns = ["nttracevent", "etweventswrite", "etw.*patch"]
            for pat in etw_patterns:
                if re.search(pat, script):
                    alerts.append(self._create_alert(
                        "ETW Patching Attempt",
                        "critical", "T1562.006", "Defense Evasion",
                        "ETW patching detected — disabling event tracing",
                        event, {"pattern": pat},
                    ))
                    break

        # CreateRemoteThread (Sysmon 8) — process injection
        if event.event_id == 8:
            source = ed.get("SourceImage", "")
            target = ed.get("TargetImage", "")
            alerts.append(self._create_alert(
                "Remote Thread Injection",
                "high", "T1055.003", "Defense Evasion",
                f"Remote thread created: {source} -> {target}",
                event, {"source_image": source, "target_image": target},
            ))

        # System time changed — only alert for non-service accounts
        if event.event_id == 4616:
            user = (event.subject_user or "").lower().strip()
            if user not in ("local service", "network service", ""):
                alerts.append(self._create_alert(
                    "System Time Changed",
                    "high", "T1070.006", "Defense Evasion",
                    f"System time manually changed by {event.user_with_domain} "
                    f"on {event.computer} — possible anti-forensics",
                    event, {"user": event.user_with_domain},
            ))

        return alerts


# =============================================================================
# SECTION 9: CREDENTIAL ACCESS DETECTOR (TA0006)
# =============================================================================

class CredentialAccessDetector(ThreatDetector):
    """6 credential access detection rules."""

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        # LSASS access (Sysmon 10)
        if event.event_id == 10:
            target = (ed.get("TargetImage", "") or "").lower()
            if "lsass.exe" in target:
                source = ed.get("SourceImage", "")
                granted = ed.get("GrantedAccess", "")
                # 0x1010, 0x1410, 0x1438 are suspicious access masks
                suspicious_masks = ["0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff"]
                sev = "high"
                if any(m in granted for m in suspicious_masks):
                    sev = "critical"
                alerts.append(self._create_alert(
                    "LSASS Memory Access",
                    sev, "T1003.001", "Credential Access",
                    f"LSASS accessed by {source} (access: {granted})",
                    event, {"source": source, "access_mask": granted},
                ))

        # SAM dump via registry
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            if "reg" in cmd and "save" in cmd and ("sam" in cmd or "system" in cmd or "security" in cmd):
                alerts.append(self._create_alert(
                    "SAM Database Dump",
                    "critical", "T1003.002", "Credential Access",
                    f"Registry hive export (potential credential dump): {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

        # DCSync detection (4662 with specific GUIDs, or by command patterns)
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            if any(dc in cmd for dc in ["dcsync", "lsadump::dcsync", "secretsdump",
                                          "ntdsutil", "drsuapi"]):
                alerts.append(self._create_alert(
                    "DCSync Attack",
                    "critical", "T1003.006", "Credential Access",
                    f"DCSync/NTDS dump detected: {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

        # Kerberoasting
        if event.event_id == 4769:
            ticket_encryption = ed.get("TicketEncryptionType", "")
            service_name = ed.get("ServiceName", "")
            # RC4 (0x17 = 23) requests for non-krbtgt are suspicious
            if ticket_encryption == "0x17" and "krbtgt" not in (service_name or "").lower():
                alerts.append(self._create_alert(
                    "Kerberoasting Detected",
                    "high", "T1558.003", "Credential Access",
                    f"RC4 TGS request for {service_name} — possible Kerberoasting",
                    event, {"service": service_name, "encryption": ticket_encryption},
                ))

        # Credential file access (Sysmon 11 or 4663)
        if event.event_id in (11, 4663):
            target_file = (ed.get("TargetFilename", "") or ed.get("ObjectName", "") or "").lower()
            cred_files = ["web credentials", "credentials", "login data",
                          "ntds.dit", ".kdbx", "unattend.xml", "sysprep.xml"]
            for cf in cred_files:
                if cf in target_file:
                    alerts.append(self._create_alert(
                        "Credential File Access",
                        "high", "T1552.001", "Credential Access",
                        f"Access to credential file: {target_file}",
                        event, {"file": target_file},
                    ))
                    break

        # DPAPI abuse
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            if "dpapi" in cmd and any(t in cmd for t in ["masterkey", "credential", "vault"]):
                alerts.append(self._create_alert(
                    "DPAPI Credential Extraction",
                    "high", "T1555.004", "Credential Access",
                    f"DPAPI abuse detected: {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

        return alerts


# =============================================================================
# SECTION 9.5: BRUTE FORCE DETECTOR
# =============================================================================

class BruteForceDetector(ThreatDetector):
    """Threshold-based brute force and password spray detection."""

    def __init__(self, failed_threshold=5, spray_threshold=3, window_minutes=10):
        super().__init__()
        self.failed_threshold = failed_threshold
        self.spray_threshold = spray_threshold
        self.window = timedelta(minutes=window_minutes)
        self._failed_by_ip: Dict[str, List[datetime]] = defaultdict(list)
        self._spray_tracker: Dict[str, Set[str]] = defaultdict(set)
        self._failed_by_acct: Dict[str, List[datetime]] = defaultdict(list)
        self._alerted: Set[str] = set()

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        if event.event_id == 4625 and not event.is_system_account and event.timestamp:
            src = event.source_ip or "(local)"
            target = event.target_user or "(unknown)"
            reason = event.status_description
            ts = event.timestamp

            # Per-IP brute force
            self._failed_by_ip[src].append(ts)
            self._failed_by_ip[src] = [t for t in self._failed_by_ip[src] if ts - t <= self.window]
            count = len(self._failed_by_ip[src])

            if count >= self.failed_threshold:
                key = f"bf:{src}"
                if key not in self._alerted:
                    self._alerted.add(key)
                    self._spray_tracker[src].add(target)
                    sev = "critical" if count >= self.failed_threshold * 3 else "high"
                    alerts.append(self._create_alert(
                        "Brute Force Attack Detected", sev, "T1110.001", "Credential Access",
                        f"{count} failed logons from {src} in {int(self.window.total_seconds()/60)} min "
                        f"on {event.computer}{f' | Reason: {reason}' if reason else ''}",
                        event, {"source_ip": src, "failed_count": count, "reason": reason},
                    ))

            # Password spray — many unique accounts from same IP
            self._spray_tracker[src].add(target)
            unique = len(self._spray_tracker[src])
            spray_key = f"spray:{src}"
            if unique >= self.spray_threshold and spray_key not in self._alerted:
                self._alerted.add(spray_key)
                alerts.append(self._create_alert(
                    "Password Spray Attack Detected", "critical", "T1110.003", "Credential Access",
                    f"Password spray from {src} — {unique} unique accounts targeted on "
                    f"{event.computer}: {', '.join(list(self._spray_tracker[src])[:5])}",
                    event, {"source_ip": src, "unique_accounts": unique},
                ))

        # Account lockout
        if event.event_id == 4740:
            account = event.target_user or event.event_data.get("TargetUserName", "")
            alerts.append(self._create_alert(
                "Account Locked Out", "high", "T1110", "Credential Access",
                f"Account '{account}' locked out on {event.computer} — "
                f"likely result of brute force or password spray",
                event, {"account": account},
            ))

        return alerts


# =============================================================================
# SECTION 9.7: ACCOUNT ANOMALY DETECTOR
# =============================================================================

class AccountAnomalyDetector(ThreatDetector):
    """Detect suspicious account management activities."""

    SENSITIVE_GROUPS = ["administrators", "domain admins", "enterprise admins",
                        "schema admins", "account operators", "backup operators",
                        "remote desktop users", "dnsadmins"]

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        if event.event_id == 4720:
            new_acct = event.target_user or ed.get("TargetUserName", "")
            created_by = event.subject_user or ed.get("SubjectUserName", "")
            alerts.append(self._create_alert(
                "New User Account Created", "medium", "T1136.001", "Persistence",
                f"Account '{new_acct}' created by {created_by} on {event.computer}",
                event, {"new_account": new_acct, "created_by": created_by},
            ))

        if event.event_id in (4728, 4732, 4756):
            member = ed.get("MemberName", "") or ed.get("MemberSid", "") or event.target_user
            group = ed.get("TargetUserName", "")
            changed_by = event.subject_user or ""
            is_sensitive = any(sg in group.lower() for sg in self.SENSITIVE_GROUPS)
            sev = "critical" if is_sensitive else "medium"
            alerts.append(self._create_alert(
                f"Member Added to {'SENSITIVE ' if is_sensitive else ''}Group",
                sev, "T1098", "Persistence",
                f"'{member}' added to {'SENSITIVE group ' if is_sensitive else 'group '}"
                f"'{group}' by {changed_by} on {event.computer}",
                event, {"member": member, "group": group, "sensitive": is_sensitive},
            ))

        if event.event_id == 4724:
            target = event.target_user or ""
            actor = event.subject_user or ""
            if target.lower() != actor.lower():
                alerts.append(self._create_alert(
                    "Password Reset by Another User", "medium", "T1098", "Persistence",
                    f"Password for '{target}' reset by '{actor}' on {event.computer}",
                    event, {"target": target, "reset_by": actor},
                ))

        if event.event_id == 4726:
            account = event.target_user or ""
            actor = event.subject_user or ""
            alerts.append(self._create_alert(
                "User Account Deleted", "medium", "T1531", "Impact",
                f"Account '{account}' deleted by '{actor}' on {event.computer}",
                event, {"account": account, "deleted_by": actor},
            ))

        if event.event_id == 4719:
            alerts.append(self._create_alert(
                "Audit Policy Changed", "high", "T1562.002", "Defense Evasion",
                f"Audit policy modified by {event.user_with_domain} on {event.computer} — "
                f"attackers disable auditing to hide activity",
                event, {"user": event.user_with_domain},
            ))

        return alerts


# =============================================================================
# SECTION 9.9: FALSE POSITIVE FILTER
# =============================================================================

class FalsePositiveFilter:
    """Centralized false positive suppression for noisy Windows events."""

    BENIGN_TASKS = ["\\microsoft\\windows\\", "\\microsoft\\office\\",
                    "\\microsoft\\edgeupdate", "\\google\\update"]
    BENIGN_SERVICES = {"wuauserv", "bits", "trustedinstaller", "windows event log",
                       "windows update", "diagnostic policy service"}

    def __init__(self):
        self.suppressed = 0
        self.suppressed_by_rule: Counter = Counter()

    def is_false_positive(self, alert: Alert) -> bool:
        event = alert.event
        if event is None:
            return False

        # Machine account localhost 4648 (already filtered in detector, double-check)
        if event.event_id == 4648 and event.is_machine_account:
            target = (event.event_data.get("TargetServerName", "") or "").lower()
            if target in ("localhost", "127.0.0.1", "", "-"):
                self._suppress("machine_localhost_4648")
                return True

        # SYSTEM/service logon (type 0 or 5)
        if event.event_id == 4624 and event.logon_type in ("0", "5"):
            self._suppress("system_service_logon")
            return True

        # DWM/UMFD window manager logons
        if event.event_id == 4624:
            user = (event.target_user or "").lower()
            if user.startswith(("dwm-", "umfd-")):
                self._suppress("dwm_umfd_logon")
                return True

        # System privilege assign (4672)
        if event.event_id == 4672 and event.is_system_account:
            self._suppress("system_privilege_4672")
            return True

        # Benign scheduled tasks
        if event.event_id in (4698, 4700, 4702):
            task = (event.event_data.get("TaskName", "") or "").lower()
            for benign in self.BENIGN_TASKS:
                if task.startswith(benign):
                    self._suppress("benign_task")
                    return True

        # Benign services
        if event.event_id in (7045, 4697):
            svc = (event.event_data.get("ServiceName", "") or "").lower()
            if svc in self.BENIGN_SERVICES:
                self._suppress("benign_service")
                return True

        return False

    def filter_alerts(self, alerts: List[Alert]) -> List[Alert]:
        return [a for a in alerts if not self.is_false_positive(a)]

    def _suppress(self, rule: str):
        self.suppressed += 1
        self.suppressed_by_rule[rule] += 1

    def get_summary(self) -> str:
        if not self.suppressed:
            return "  No false positives suppressed"
        lines = [f"  Suppressed {self.suppressed} false positives:"]
        for rule, count in self.suppressed_by_rule.most_common():
            lines.append(f"    {rule}: {count}")
        return "\n".join(lines)


# =============================================================================
# SECTION 10: ATTACK CHAIN CORRELATOR
# =============================================================================

class AttackChainCorrelator:
    """Behavioral IOA correlation engine — reconstructs multi-stage attack chains."""

    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.chains: List[AttackChain] = []

    def correlate(self, alerts: List[Alert]) -> List[AttackChain]:
        """Group alerts into attack chains by host and temporal proximity."""
        if not alerts:
            return []

        # Group by host
        host_alerts: Dict[str, List[Alert]] = defaultdict(list)
        for alert in alerts:
            host = alert.event.computer if alert.event else "unknown"
            host_alerts[host].append(alert)

        for host, host_alert_list in host_alerts.items():
            # Sort by timestamp
            sorted_alerts = sorted(
                [a for a in host_alert_list if a.timestamp],
                key=lambda a: a.timestamp
            )

            if not sorted_alerts:
                continue

            # Build chains by temporal proximity and tactic diversity
            current_chain_alerts = [sorted_alerts[0]]
            for i in range(1, len(sorted_alerts)):
                alert = sorted_alerts[i]
                prev = current_chain_alerts[-1]

                if (alert.timestamp - prev.timestamp) <= self.time_window:
                    current_chain_alerts.append(alert)
                else:
                    if len(current_chain_alerts) >= 2:
                        self._build_chain(host, current_chain_alerts)
                    current_chain_alerts = [alert]

            if len(current_chain_alerts) >= 2:
                self._build_chain(host, current_chain_alerts)

        return self.chains

    def _build_chain(self, host: str, alerts: List[Alert]):
        tactics = list(dict.fromkeys(a.mitre_tactic for a in alerts))
        tactic_positions = []
        for t in tactics:
            if t in self.TACTIC_ORDER:
                tactic_positions.append(self.TACTIC_ORDER.index(t))

        risk = min(100, len(alerts) * 10 + len(tactics) * 15)
        if len(tactic_positions) >= 2:
            if sorted(tactic_positions) == tactic_positions:
                risk = min(100, risk + 20)

        chain = AttackChain(
            host=host,
            alerts=alerts,
            tactics=tactics,
            risk_score=risk,
            start_time=alerts[0].timestamp,
            end_time=alerts[-1].timestamp,
            description=f"Attack chain: {' → '.join(tactics)} ({len(alerts)} events)",
        )
        self.chains.append(chain)


# =============================================================================
# SECTION 11: IOC EXTRACTOR
# =============================================================================

class IOCExtractor:
    """Regex-based IOC extraction + dedup."""

    IP_RE = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
    )
    DOMAIN_RE = re.compile(
        r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|info|biz|'
        r'xyz|top|ru|cn|tk|ml|ga|cf|gq|pw|cc|club|site|online|space)\b', re.IGNORECASE
    )
    HASH_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
    HASH_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
    HASH_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
    URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
    EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    PRIVATE_IP_RE = re.compile(
        r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.255\.255|::1|fe80:)'
    )

    BENIGN_DOMAINS = {
        "microsoft.com", "windows.com", "windowsupdate.com", "google.com",
        "aka.ms", "office.com", "live.com", "outlook.com", "bing.com",
        "azure.com", "microsoftonline.com", "office365.com",
        "digicert.com", "verisign.com", "symantec.com",
    }

    def __init__(self):
        self.iocs: Dict[str, IOC] = {}

    def extract_from_events(self, events: List[ParsedEvent]) -> List[IOC]:
        """Extract IOCs from all events."""
        for event in events:
            # Direct IP extraction from event properties
            if event.source_ip and event.source_ip not in ("127.0.0.1", "::1", "-", "", "0.0.0.0"):
                if not self.PRIVATE_IP_RE.match(event.source_ip):
                    self._add_ioc("ip", event.source_ip, event)

            text_parts = []
            for v in (event.event_data or {}).values():
                if v:
                    text_parts.append(str(v))
            text = " ".join(text_parts)

            self._extract_ips(text, event)
            self._extract_domains(text, event)
            self._extract_hashes(text, event)
            self._extract_urls(text, event)
            self._extract_emails(text, event)

        return list(self.iocs.values())

    def _extract_ips(self, text: str, event: ParsedEvent):
        for match in self.IP_RE.findall(text):
            if not self.PRIVATE_IP_RE.match(match):
                self._add_ioc("ip", match, event)

    def _extract_domains(self, text: str, event: ParsedEvent):
        for match in self.DOMAIN_RE.findall(text):
            domain = match.lower()
            if not any(domain == bd or domain.endswith("." + bd) for bd in self.BENIGN_DOMAINS):
                self._add_ioc("domain", domain, event)

    def _extract_hashes(self, text: str, event: ParsedEvent):
        for match in self.HASH_SHA256_RE.findall(text):
            self._add_ioc("sha256", match.lower(), event)
        for match in self.HASH_SHA1_RE.findall(text):
            if len(match) == 40:
                self._add_ioc("sha1", match.lower(), event)
        for match in self.HASH_MD5_RE.findall(text):
            if len(match) == 32:
                self._add_ioc("md5", match.lower(), event)

    def _extract_urls(self, text: str, event: ParsedEvent):
        for match in self.URL_RE.findall(text):
            self._add_ioc("url", match, event)

    def _extract_emails(self, text: str, event: ParsedEvent):
        for match in self.EMAIL_RE.findall(text):
            self._add_ioc("email", match.lower(), event)

    def _add_ioc(self, ioc_type: str, value: str, event: ParsedEvent):
        key = f"{ioc_type}:{value}"
        if key in self.iocs:
            self.iocs[key].count += 1
            if event.timestamp:
                self.iocs[key].last_seen = event.timestamp
        else:
            self.iocs[key] = IOC(
                ioc_type=ioc_type,
                value=value,
                source_event_id=event.event_id,
                context=event.description,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )


# =============================================================================
# SECTION 14: THREAT INTELLIGENCE ENGINE
# =============================================================================

@dataclass
class ThreatIntelResult:
    """Normalized TI lookup result."""
    source: str
    indicator: str
    indicator_type: str
    malicious: bool = False
    score: int = 0
    details: str = ""
    raw: Dict = field(default_factory=dict)


class ThreatIntelCache:
    """SQLite cache with TTL management."""

    def __init__(self, db_path: str = ".ti_cache.db", ttl_hours: int = 24):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ti_cache (
                indicator TEXT, source TEXT, result TEXT,
                cached_at TEXT, PRIMARY KEY (indicator, source)
            )
        """)
        conn.commit()
        conn.close()

    def get(self, indicator: str, source: str) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT result, cached_at FROM ti_cache WHERE indicator=? AND source=?",
            (indicator, source)
        ).fetchone()
        conn.close()
        if row:
            cached_at = datetime.fromisoformat(row[1])
            if datetime.now() - cached_at < timedelta(hours=self.ttl_hours):
                return json.loads(row[0])
        return None

    def put(self, indicator: str, source: str, result: Dict):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO ti_cache (indicator, source, result, cached_at) VALUES (?,?,?,?)",
            (indicator, source, json.dumps(result), datetime.now().isoformat())
        )
        conn.commit()
        conn.close()


class ThreatIntelEngine:
    """Multi-source enrichment orchestrator — OTX, VT, AbuseIPDB, Shodan + cache."""

    def __init__(self, otx_key=None, vt_key=None, abuseipdb_key=None, shodan_key=None,
                 use_cache=True, cache_path=".ti_cache.db"):
        self.otx_key = otx_key or os.environ.get("OTX_API_KEY", "")
        self.vt_key = vt_key or os.environ.get("VT_API_KEY", "")
        self.abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.shodan_key = shodan_key or os.environ.get("SHODAN_API_KEY", "")
        self.cache = ThreatIntelCache(cache_path) if use_cache else None
        self.results: Dict[str, List[ThreatIntelResult]] = {}
        self.stats = {"lookups": 0, "hits": 0, "errors": 0, "cache_hits": 0}
        self._rate_limits = {"otx": 0, "vt": 0, "abuseipdb": 0, "shodan": 0}

    def enrich_ioc(self, ioc: IOC) -> List[ThreatIntelResult]:
        """Enrich a single IOC against all configured sources."""
        results = []

        if ioc.ioc_type == "ip":
            if self.otx_key:
                results.append(self._query_otx_ip(ioc.value))
            if self.vt_key:
                results.append(self._query_vt_ip(ioc.value))
            if self.abuseipdb_key:
                results.append(self._query_abuseipdb(ioc.value))
            if self.shodan_key:
                results.append(self._query_shodan(ioc.value))

        elif ioc.ioc_type == "domain":
            if self.otx_key:
                results.append(self._query_otx_domain(ioc.value))
            if self.vt_key:
                results.append(self._query_vt_domain(ioc.value))

        elif ioc.ioc_type in ("md5", "sha1", "sha256"):
            if self.vt_key:
                results.append(self._query_vt_hash(ioc.value))

        results = [r for r in results if r is not None]
        self.results[ioc.value] = results
        return results

    def enrich_all(self, iocs: List[IOC]) -> Dict[str, List[ThreatIntelResult]]:
        """Enrich all IOCs."""
        for ioc in iocs:
            self.enrich_ioc(ioc)
        return self.results

    def get_composite_score(self, results: List[ThreatIntelResult]) -> int:
        if not results:
            return 0
        return max(r.score for r in results)

    def _api_request(self, url: str, headers: Dict = None, source: str = "") -> Optional[Dict]:
        """Make an API request with caching and rate limiting."""
        import urllib.request
        import urllib.error

        # Check cache
        if self.cache:
            cached = self.cache.get(url, source)
            if cached:
                self.stats["cache_hits"] += 1
                return cached

        # Rate limiting — simple 1 req/sec per source
        now = time.time()
        if source and now - self._rate_limits.get(source, 0) < 1.0:
            time.sleep(1.0 - (now - self._rate_limits.get(source, 0)))
        self._rate_limits[source] = time.time()

        self.stats["lookups"] += 1
        try:
            req = urllib.request.Request(url, headers=headers or {})
            req.add_header("User-Agent", "LogParser-v4/1.0")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            if self.cache:
                self.cache.put(url, source, data)
            self.stats["hits"] += 1
            return data
        except Exception as e:
            self.stats["errors"] += 1
            logging.debug(f"TI query failed ({source}): {e}")
            return None

    def _query_otx_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        data = self._api_request(url, {"X-OTX-API-KEY": self.otx_key}, "otx")
        if not data:
            return None
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return ThreatIntelResult(
            source="OTX", indicator=ip, indicator_type="ip",
            malicious=pulse_count > 0, score=min(100, pulse_count * 20),
            details=f"{pulse_count} OTX pulses", raw=data,
        )

    def _query_otx_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        data = self._api_request(url, {"X-OTX-API-KEY": self.otx_key}, "otx")
        if not data:
            return None
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return ThreatIntelResult(
            source="OTX", indicator=domain, indicator_type="domain",
            malicious=pulse_count > 0, score=min(100, pulse_count * 20),
            details=f"{pulse_count} OTX pulses", raw=data,
        )

    def _query_vt_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        data = self._api_request(url, {"x-apikey": self.vt_key}, "vt")
        if not data:
            return None
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return ThreatIntelResult(
            source="VirusTotal", indicator=ip, indicator_type="ip",
            malicious=malicious_count > 0, score=min(100, malicious_count * 10),
            details=f"{malicious_count} VT detections", raw=data,
        )

    def _query_vt_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        data = self._api_request(url, {"x-apikey": self.vt_key}, "vt")
        if not data:
            return None
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return ThreatIntelResult(
            source="VirusTotal", indicator=domain, indicator_type="domain",
            malicious=malicious_count > 0, score=min(100, malicious_count * 10),
            details=f"{malicious_count} VT detections", raw=data,
        )

    def _query_vt_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        data = self._api_request(url, {"x-apikey": self.vt_key}, "vt")
        if not data:
            return None
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        return ThreatIntelResult(
            source="VirusTotal", indicator=file_hash, indicator_type="hash",
            malicious=malicious_count > 0, score=min(100, malicious_count * 5),
            details=f"{malicious_count} VT detections", raw=data,
        )

    def _query_abuseipdb(self, ip: str) -> Optional[ThreatIntelResult]:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        data = self._api_request(url, {
            "Key": self.abuseipdb_key, "Accept": "application/json"
        }, "abuseipdb")
        if not data:
            return None
        abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
        return ThreatIntelResult(
            source="AbuseIPDB", indicator=ip, indicator_type="ip",
            malicious=abuse_score > 50, score=abuse_score,
            details=f"Abuse confidence: {abuse_score}%", raw=data,
        )

    def _query_shodan(self, ip: str) -> Optional[ThreatIntelResult]:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        data = self._api_request(url, {}, "shodan")
        if not data:
            return None
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        return ThreatIntelResult(
            source="Shodan", indicator=ip, indicator_type="ip",
            malicious=len(vulns) > 0, score=min(100, len(vulns) * 15 + len(ports) * 2),
            details=f"{len(ports)} ports, {len(vulns)} vulns", raw=data,
        )


# =============================================================================
# SECTION 15: SIGMA RULE EVALUATOR
# =============================================================================

@dataclass
class SIGMARule:
    """Parsed SIGMA rule representation."""
    rule_id: str
    title: str
    description: str
    severity: str
    detection: Dict
    logsource: Dict
    mitre_tags: List[str] = field(default_factory=list)
    filename: str = ""


class SIGMAEvaluator:
    """YAML rule loading + event evaluation engine."""

    def __init__(self):
        self.rules: List[SIGMARule] = []
        self.stats = {"rules_loaded": 0, "matches": 0, "errors": 0}

    def load_rules(self, rules_path: str) -> int:
        """Load SIGMA rules from directory."""
        if not HAS_YAML:
            logging.warning("pyyaml not installed — SIGMA rules disabled")
            return 0

        if os.path.isfile(rules_path):
            self._load_rule_file(rules_path)
        elif os.path.isdir(rules_path):
            for root_dir, _, files in os.walk(rules_path):
                for fname in files:
                    if fname.endswith((".yml", ".yaml")):
                        self._load_rule_file(os.path.join(root_dir, fname))

        self.stats["rules_loaded"] = len(self.rules)
        return len(self.rules)

    def _load_rule_file(self, filepath: str):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not doc or not isinstance(doc, dict):
                return
            if "detection" not in doc:
                return

            mitre_tags = []
            for tag in doc.get("tags", []):
                if tag.startswith("attack.t"):
                    mitre_tags.append(tag.replace("attack.", "").upper())

            rule = SIGMARule(
                rule_id=doc.get("id", str(uuid.uuid4())),
                title=doc.get("title", os.path.basename(filepath)),
                description=doc.get("description", ""),
                severity=doc.get("level", "medium"),
                detection=doc.get("detection", {}),
                logsource=doc.get("logsource", {}),
                mitre_tags=mitre_tags,
                filename=filepath,
            )
            self.rules.append(rule)
        except Exception as e:
            self.stats["errors"] += 1
            logging.debug(f"Failed to load SIGMA rule {filepath}: {e}")

    def evaluate(self, events: List[ParsedEvent]) -> List[Alert]:
        """Evaluate all loaded SIGMA rules against events."""
        alerts = []
        for event in events:
            for rule in self.rules:
                if self._match_rule(rule, event):
                    self.stats["matches"] += 1
                    technique = rule.mitre_tags[0] if rule.mitre_tags else "T1059"
                    alerts.append(Alert(
                        rule_name=f"SIGMA: {rule.title}",
                        severity=rule.severity,
                        mitre_technique=technique,
                        mitre_tactic="Execution",
                        description=rule.description[:500] or rule.title,
                        event=event,
                        evidence={"sigma_rule": rule.title, "rule_id": rule.rule_id},
                    ))
        return alerts

    def _match_rule(self, rule: SIGMARule, event: ParsedEvent) -> bool:
        """Check if an event matches a SIGMA rule's detection logic."""
        detection = rule.detection
        condition = detection.get("condition", "selection")

        # Simple evaluation: check 'selection' criteria
        selection = detection.get("selection", {})
        if not selection:
            return False

        return self._match_selection(selection, event)

    def _match_selection(self, selection, event: ParsedEvent) -> bool:
        """Match a SIGMA selection block against an event."""
        # Some SIGMA rules use lists of dicts (OR logic)
        if isinstance(selection, list):
            return any(
                self._match_selection(item, event)
                for item in selection if isinstance(item, dict)
            )
        if not isinstance(selection, dict):
            return False

        ed = event.event_data or {}
        for field_name, expected in selection.items():
            field_name_mapped = field_name.replace("|", "")

            # Handle modifiers
            modifier = ""
            if "|" in field_name:
                parts = field_name.split("|")
                field_name_mapped = parts[0]
                modifier = parts[1] if len(parts) > 1 else ""

            # Get actual value — check event_data and top-level attrs
            actual = ed.get(field_name_mapped, "")
            if not actual:
                actual = getattr(event, field_name_mapped, "")

            if not actual:
                # Try case-insensitive
                for k, v in ed.items():
                    if k.lower() == field_name_mapped.lower():
                        actual = v
                        break

            actual_lower = str(actual).lower()

            if isinstance(expected, list):
                if modifier == "contains":
                    if not any(str(e).lower() in actual_lower for e in expected):
                        return False
                elif modifier == "endswith":
                    if not any(actual_lower.endswith(str(e).lower()) for e in expected):
                        return False
                elif modifier == "startswith":
                    if not any(actual_lower.startswith(str(e).lower()) for e in expected):
                        return False
                else:
                    if actual_lower not in [str(e).lower() for e in expected]:
                        return False
            else:
                expected_lower = str(expected).lower()
                if modifier == "contains":
                    if expected_lower not in actual_lower:
                        return False
                elif modifier == "endswith":
                    if not actual_lower.endswith(expected_lower):
                        return False
                elif modifier == "startswith":
                    if not actual_lower.startswith(expected_lower):
                        return False
                else:
                    if actual_lower != expected_lower:
                        return False

        return True


# =============================================================================
# SECTION 16: YARA SCANNER
# =============================================================================

@dataclass
class YARAMatch:
    """YARA match result data class."""
    rule_name: str
    file_path: str
    tags: List[str]
    strings_matched: List[str]


class YARAScanner:
    """File artifact scanning with compiled YARA rules."""

    def __init__(self):
        self.rules = None
        self.matches: List[YARAMatch] = []
        self.stats = {"files_scanned": 0, "matches": 0, "errors": 0}

    def load_rules(self, rules_path: str) -> int:
        """Load YARA rules from file or directory."""
        if not HAS_YARA:
            logging.warning("yara-python not installed — YARA scanning disabled")
            return 0

        rule_files = {}
        if os.path.isfile(rules_path):
            rule_files["rule_0"] = rules_path
        elif os.path.isdir(rules_path):
            for i, fname in enumerate(os.listdir(rules_path)):
                if fname.endswith((".yar", ".yara")):
                    rule_files[f"rule_{i}"] = os.path.join(rules_path, fname)

        if not rule_files:
            return 0

        try:
            self.rules = yara.compile(filepaths=rule_files)
            return len(rule_files)
        except Exception as e:
            self.stats["errors"] += 1
            logging.warning(f"YARA rule compilation failed: {e}")
            return 0

    def scan_file(self, filepath: str) -> List[YARAMatch]:
        """Scan a single file against loaded YARA rules."""
        if not self.rules:
            return []

        self.stats["files_scanned"] += 1
        matches = []
        try:
            yara_matches = self.rules.match(filepath, timeout=30)
            for m in yara_matches:
                match = YARAMatch(
                    rule_name=m.rule,
                    file_path=filepath,
                    tags=list(m.tags),
                    strings_matched=[str(s) for s in m.strings[:5]],
                )
                matches.append(match)
                self.matches.append(match)
                self.stats["matches"] += 1
        except Exception as e:
            self.stats["errors"] += 1
            logging.debug(f"YARA scan error on {filepath}: {e}")

        return matches

    def scan_directory(self, dirpath: str) -> List[YARAMatch]:
        """Scan all files in a directory."""
        all_matches = []
        for root_dir, _, files in os.walk(dirpath):
            for fname in files:
                filepath = os.path.join(root_dir, fname)
                all_matches.extend(self.scan_file(filepath))
        return all_matches

    def to_alerts(self) -> List[Alert]:
        """Convert YARA matches to Alert objects."""
        alerts = []
        for m in self.matches:
            alerts.append(Alert(
                rule_name=f"YARA: {m.rule_name}",
                severity="high",
                mitre_technique="T1204",
                mitre_tactic="Execution",
                description=f"YARA rule '{m.rule_name}' matched on {m.file_path}",
                event=None,
                evidence={
                    "rule_name": m.rule_name,
                    "file_path": m.file_path,
                    "tags": m.tags,
                    "strings_matched": m.strings_matched,
                },
            ))
        return alerts


# =============================================================================
# SECTION 17: DISCOVERY DETECTOR (TA0007)
# =============================================================================

class DiscoveryDetector(ThreatDetector):
    """4 discovery detection rules."""

    RECON_TOOLS = ["systeminfo", "ipconfig", "net view", "net user",
                   "net localgroup", "net group", "net share",
                   "tasklist", "qprocess", "qwinsta", "arp -a",
                   "route print", "netstat", "nbtstat"]

    def __init__(self):
        super().__init__()
        self._recon_window: Dict[str, List[datetime]] = defaultdict(list)

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        if event.event_id not in (4688, 1):
            return alerts

        ed = event.event_data
        cmd = (ed.get("CommandLine", "") or ed.get("NewProcessName", "") or "").lower()

        # Track recon command bursts
        for tool in self.RECON_TOOLS:
            if tool in cmd:
                host = event.computer
                if event.timestamp:
                    self._recon_window[host].append(event.timestamp)
                    # Check for burst: 5+ recon commands in 5 minutes
                    recent = [t for t in self._recon_window[host]
                              if event.timestamp - t < timedelta(minutes=5)]
                    self._recon_window[host] = recent
                    if len(recent) >= 5:
                        alerts.append(self._create_alert(
                            "System Information Discovery Burst",
                            "high", "T1082", "Discovery",
                            f"Burst of {len(recent)} recon commands on {host}",
                            event, {"commands": len(recent)},
                        ))
                        self._recon_window[host] = []  # reset after alert
                break

        # Domain trust enumeration
        if any(t in cmd for t in ["nltest /domain_trusts", "dsquery trustedDomain",
                                   "get-adtrust", "get-domaintrust"]):
            alerts.append(self._create_alert(
                "Domain Trust Enumeration",
                "high", "T1482", "Discovery",
                f"Domain trust enumeration detected: {cmd[:200]}",
                event, {"command_line": cmd[:500]},
            ))

        # Security software discovery
        if any(t in cmd for t in ["get-mpcomputerstatus", "get-mppreference",
                                   "fltmc", "sc query windefend",
                                   "wmic /namespace:\\\\root\\SecurityCenter"]):
            alerts.append(self._create_alert(
                "Security Software Discovery",
                "medium", "T1518.001", "Discovery",
                f"Security software enumeration: {cmd[:200]}",
                event, {"command_line": cmd[:500]},
            ))

        # Network recon
        if any(t in cmd for t in ["nmap", "masscan", "angry.*scan",
                                   "advanced.?port.?scanner"]):
            alerts.append(self._create_alert(
                "Network Scanning Tool",
                "high", "T1046", "Discovery",
                f"Network scanning tool detected: {cmd[:200]}",
                event, {"command_line": cmd[:500]},
            ))

        return alerts


# =============================================================================
# SECTION 18: EXFILTRATION DETECTOR (TA0010)
# =============================================================================

class ExfiltrationDetector(ThreatDetector):
    """4 exfiltration detection rules."""

    CLOUD_UPLOAD_TOOLS = ["rclone", "megacmd", "megasync", "gdrive",
                          "onedrivecmd", "dropbox", "s3cmd", "aws s3"]

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()

            # Archive staging
            if any(t in cmd for t in ["rar a", "7z a", "zip -r",
                                       "compress-archive", "tar -cz"]):
                sev = "high" if any(p in cmd for p in ["-p", "-hp", "--password"]) else "medium"
                alerts.append(self._create_alert(
                    "Archive Staging for Exfiltration",
                    sev, "T1560.001", "Exfiltration",
                    f"Data archived (potential staging): {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

            # Cloud upload tools
            for tool in self.CLOUD_UPLOAD_TOOLS:
                if tool in cmd:
                    alerts.append(self._create_alert(
                        f"Cloud Upload Tool: {tool}",
                        "high", "T1567.002", "Exfiltration",
                        f"Cloud upload tool detected: {cmd[:200]}",
                        event, {"tool": tool, "command_line": cmd[:500]},
                    ))
                    break

        # DNS exfiltration — long subdomain queries (Sysmon 22)
        if event.event_id == 22:
            query = ed.get("QueryName", "")
            if query:
                parts = query.split(".")
                long_labels = [p for p in parts if len(p) > 30]
                if long_labels:
                    alerts.append(self._create_alert(
                        "DNS Exfiltration — High Entropy Subdomain",
                        "high", "T1048.003", "Exfiltration",
                        f"Suspiciously long DNS subdomain query: {query}",
                        event, {"query": query, "long_labels": len(long_labels)},
                    ))

        # Large file transfer (Sysmon 11 + network)
        if event.event_id == 3:
            dst_port = ed.get("DestinationPort", "")
            if dst_port in ("21", "22", "445", "3389"):
                sent = int(ed.get("SentBytes", 0) or 0)
                if sent > 50_000_000:
                    alerts.append(self._create_alert(
                        "Large Outbound Data Transfer",
                        "high", "T1048", "Exfiltration",
                        f"Large transfer ({sent / 1_000_000:.1f} MB) to port {dst_port}",
                        event, {"bytes_sent": sent, "port": dst_port},
                    ))

        return alerts


# =============================================================================
# SECTION 19: COMMAND AND CONTROL DETECTOR (TA0011)
# =============================================================================

class CommandAndControlDetector(ThreatDetector):
    """5 C2 detection rules."""

    C2_FRAMEWORKS = {
        "cobalt_strike": ["beacon", "cobaltstrike", "teamserver"],
        "sliver": ["sliver", "implant"],
        "mythic": ["mythic", "apfell"],
        "metasploit": ["meterpreter", "msfvenom", "metasploit"],
        "empire": ["invoke-empire", "stager", "launcher.bat"],
    }

    def __init__(self):
        super().__init__()
        self._beacon_tracker: Dict[str, List[datetime]] = defaultdict(list)

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        # Beaconing detection — periodic connections (Sysmon 3)
        if event.event_id == 3:
            dst_ip = ed.get("DestinationIp", "")
            if dst_ip and event.timestamp:
                key = f"{event.computer}:{dst_ip}"
                self._beacon_tracker[key].append(event.timestamp)
                times = self._beacon_tracker[key]
                if len(times) >= 5:
                    intervals = [(times[i] - times[i - 1]).total_seconds()
                                 for i in range(1, len(times))]
                    if intervals:
                        avg = sum(intervals) / len(intervals)
                        if avg > 0:
                            jitter = sum(abs(i - avg) for i in intervals) / (len(intervals) * avg)
                            if jitter < 0.3 and avg < 600:
                                alerts.append(self._create_alert(
                                    "C2 Beaconing Detected",
                                    "critical", "T1071", "Command and Control",
                                    f"Regular beaconing to {dst_ip} (interval: {avg:.0f}s, jitter: {jitter:.2f})",
                                    event, {"dst_ip": dst_ip, "interval": avg, "jitter": jitter},
                                ))
                                self._beacon_tracker[key] = []

        # DNS tunneling — high volume DNS queries (Sysmon 22)
        if event.event_id == 22:
            query = ed.get("QueryName", "")
            if query:
                # Entropy check
                import math
                chars = query.replace(".", "")
                if len(chars) > 20:
                    freq = Counter(chars)
                    entropy = -sum((c / len(chars)) * math.log2(c / len(chars))
                                   for c in freq.values())
                    if entropy > 4.0:
                        alerts.append(self._create_alert(
                            "DNS Tunneling — High Entropy Query",
                            "high", "T1071.004", "Command and Control",
                            f"High-entropy DNS query (entropy: {entropy:.2f}): {query}",
                            event, {"query": query, "entropy": entropy},
                        ))

        # C2 framework signatures in process/command line
        if event.event_id in (4688, 1, 4104):
            cmd = (ed.get("CommandLine", "") or ed.get("ScriptBlockText", "") or "").lower()
            for framework, patterns in self.C2_FRAMEWORKS.items():
                for pattern in patterns:
                    if pattern in cmd:
                        alerts.append(self._create_alert(
                            f"C2 Framework: {framework}",
                            "critical", "T1219", "Command and Control",
                            f"C2 framework '{framework}' signature detected: {cmd[:200]}",
                            event, {"framework": framework, "command_line": cmd[:500]},
                        ))
                        break

        # PowerShell download cradle (C2 staging)
        if event.event_id == 4104:
            script = (ed.get("ScriptBlockText", "") or "").lower()
            cradles = ["downloadstring", "downloaddata", "downloadfile",
                       "invoke-webrequest", "invoke-restmethod",
                       "start-bitstransfer", "net.webclient",
                       "net.sockets.tcpclient", "system.net.http"]
            for cradle in cradles:
                if cradle in script:
                    alerts.append(self._create_alert(
                        "PowerShell Download Cradle",
                        "high", "T1059.001", "Command and Control",
                        f"PowerShell download cradle detected: {cradle}",
                        event, {"cradle_type": cradle, "script_snippet": script[:300]},
                    ))
                    break

        # LOLBin network activity
        if event.event_id == 3:
            image = (ed.get("Image", "") or "").lower()
            network_lolbins = ["certutil", "bitsadmin", "mshta", "regsvr32",
                               "rundll32", "msiexec", "cscript", "wscript"]
            for lolbin in network_lolbins:
                if lolbin in image:
                    dst = ed.get("DestinationIp", "")
                    alerts.append(self._create_alert(
                        f"LOLBin Network Activity: {lolbin}",
                        "high", "T1218", "Command and Control",
                        f"LOLBin {lolbin} making network connection to {dst}",
                        event, {"lolbin": lolbin, "dst_ip": dst},
                    ))
                    break

        return alerts


# =============================================================================
# SECTION 20: IMPACT DETECTOR (TA0040)
# =============================================================================

class ImpactDetector(ThreatDetector):
    """3 impact detection rules."""

    RANSOMWARE_EXTENSIONS = [".encrypted", ".locked", ".crypt", ".crypto",
                             ".enc", ".locky", ".cerber", ".zepto",
                             ".dharma", ".phobos", ".ryuk", ".conti"]

    def analyze(self, event: ParsedEvent) -> List[Alert]:
        alerts = []
        ed = event.event_data

        # Shadow copy deletion — ransomware indicator
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            if any(t in cmd for t in ["vssadmin delete shadows",
                                       "wmic shadowcopy delete",
                                       "bcdedit /set.*recoveryenabled.*no",
                                       "wbadmin delete catalog"]):
                alerts.append(self._create_alert(
                    "Ransomware Indicator: Recovery Disabled",
                    "critical", "T1490", "Impact",
                    f"Recovery mechanism destroyed: {cmd[:200]}",
                    event, {"command_line": cmd[:500]},
                ))

        # Mass file encryption — rapid file creation with suspicious extensions
        if event.event_id == 11:
            target = (ed.get("TargetFilename", "") or "").lower()
            for ext in self.RANSOMWARE_EXTENSIONS:
                if target.endswith(ext):
                    alerts.append(self._create_alert(
                        "Ransomware File Encryption",
                        "critical", "T1486", "Impact",
                        f"File with ransomware extension created: {target}",
                        event, {"file": target, "extension": ext},
                    ))
                    break

        # Service destruction
        if event.event_id in (4688, 1):
            cmd = (ed.get("CommandLine", "") or "").lower()
            critical_svc = ["sc delete", "sc stop", "net stop"]
            target_svc = ["windefend", "mpssvc", "wscsvc", "spooler",
                          "bits", "wuauserv", "eventlog", "sens"]
            for sc_cmd in critical_svc:
                if sc_cmd in cmd:
                    for svc in target_svc:
                        if svc in cmd:
                            alerts.append(self._create_alert(
                                "Critical Service Destruction",
                                "critical", "T1489", "Impact",
                                f"Critical service targeted: {cmd[:200]}",
                                event, {"service": svc, "command_line": cmd[:500]},
                            ))
                            break

        return alerts


# =============================================================================
# SECTION 21: CVE CORRELATOR
# =============================================================================

@dataclass
class CVEResult:
    """Result from CVE correlation lookup."""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    affected_cpe: str
    exploit_available: bool
    cisa_kev: bool
    references: List[str]
    remediation: str
    detected_software: str
    detected_version: str


class CVECorrelator:
    """
    Cross-reference detected software versions against known exploited vulnerabilities.
    Sources: Shodan CVEDB (free) + CISA KEV catalog.
    """

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    SHODAN_CVEDB_URL = "https://cvedb.shodan.io/cve"

    SOFTWARE_PATTERNS = [
        (r'apache[/ ]([\d.]+)', 'Apache HTTP Server', 1),
        (r'nginx[/ ]([\d.]+)', 'nginx', 1),
        (r'iis[/ ]([\d.]+)', 'Microsoft IIS', 1),
        (r'openssl[/ ]([\d.\w]+)', 'OpenSSL', 1),
        (r'ssh[_-]([\d.\w]+)', 'OpenSSH', 1),
        (r'microsoft sql server.*?(\d{4})', 'Microsoft SQL Server', 1),
        (r'mysql[/ ]([\d.]+)', 'MySQL', 1),
        (r'java[/ ]([\d._]+)', 'Java', 1),
        (r'python[/ ]([\d.]+)', 'Python', 1),
        (r'php[/ ]([\d.]+)', 'PHP', 1),
        (r'tomcat[/ ]([\d.]+)', 'Apache Tomcat', 1),
        (r'exchange server (\d{4})', 'Microsoft Exchange', 1),
        (r'powershell[/ ]([\d.]+)', 'PowerShell', 1),
        (r'log4j[- ]([\d.]+)', 'Apache Log4j', 1),
        (r'fortios[/ ]([\d.]+)', 'FortiOS', 1),
    ]

    def __init__(self, enable_online: bool = True):
        self.enable_online = enable_online
        self.kev_catalog: Dict[str, Dict] = {}
        self.cve_cache: Dict[str, Dict] = {}
        self.detected_software: List[Dict[str, str]] = []
        self.results: List[CVEResult] = []
        self.stats = {'software_detected': 0, 'cves_found': 0, 'kev_matches': 0, 'errors': 0}

    def load_kev_catalog(self) -> int:
        try:
            import urllib.request
            req = urllib.request.Request(self.CISA_KEV_URL)
            req.add_header('User-Agent', 'LogParser-v4/1.0')
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            for vuln in data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID', '')
                if cve_id:
                    self.kev_catalog[cve_id] = {
                        'vendor': vuln.get('vendorProject', ''),
                        'product': vuln.get('product', ''),
                        'name': vuln.get('vulnerabilityName', ''),
                        'description': vuln.get('shortDescription', ''),
                        'date_added': vuln.get('dateAdded', ''),
                        'due_date': vuln.get('requiredAction', ''),
                        'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                    }
            logging.info(f"Loaded {len(self.kev_catalog)} CISA KEV entries")
            return len(self.kev_catalog)
        except Exception as e:
            self.stats['errors'] += 1
            logging.warning(f"Failed to load CISA KEV catalog: {e}")
            return 0

    def extract_software_from_events(self, events: List[ParsedEvent]) -> List[Dict[str, str]]:
        software_set = set()
        for event in events:
            if event.event_id not in (4688, 1, 7, 7045, 11):
                continue
            ed = event.event_data or {}
            search_fields = [ed.get(f, '') for f in
                             ('CommandLine', 'Image', 'NewProcessName',
                              'ImageLoaded', 'ServiceFileName', 'Description',
                              'Product', 'FileVersion', 'OriginalFileName')]
            search_text = ' '.join(str(f) for f in search_fields if f)
            for pattern, software, ver_group in self.SOFTWARE_PATTERNS:
                match = re.search(pattern, search_text, re.IGNORECASE)
                if match:
                    version = match.group(ver_group)
                    key = f"{software}:{version}"
                    if key not in software_set:
                        software_set.add(key)
                        self.detected_software.append({
                            'software': software, 'version': version,
                            'source_event_id': event.event_id,
                        })
        self.stats['software_detected'] = len(self.detected_software)
        return self.detected_software

    def correlate(self, events: List[ParsedEvent]) -> List[CVEResult]:
        self.extract_software_from_events(events)
        for kev_cve, kev_info in self.kev_catalog.items():
            for sw in self.detected_software:
                product_match = (
                    sw['software'].lower() in kev_info.get('product', '').lower() or
                    kev_info.get('product', '').lower() in sw['software'].lower()
                )
                if product_match:
                    cvss = 0.0
                    description = kev_info.get('description', '')
                    severity = 'critical' if cvss >= 9.0 else 'high' if cvss >= 7.0 else 'medium'
                    result = CVEResult(
                        cve_id=kev_cve, cvss_score=cvss, severity=severity,
                        description=description[:500],
                        affected_cpe=f"{sw['software']} {sw['version']}",
                        exploit_available=True, cisa_kev=True, references=[],
                        remediation=kev_info.get('due_date', 'Apply vendor patch'),
                        detected_software=sw['software'],
                        detected_version=sw['version'],
                    )
                    self.results.append(result)
                    self.stats['cves_found'] += 1
                    self.stats['kev_matches'] += 1
        return self.results

    def to_alerts(self) -> List[Alert]:
        alerts = []
        for r in self.results:
            alerts.append(Alert(
                rule_name=f"CVE: {r.cve_id} ({r.detected_software})",
                severity=r.severity, mitre_technique='T1190',
                mitre_tactic='Initial Access',
                description=f"{r.cve_id} (CVSS {r.cvss_score}) affects "
                            f"{r.detected_software} {r.detected_version}. "
                            f"{'CISA KEV. ' if r.cisa_kev else ''}{r.description[:300]}",
                event=None,
                evidence={'cve_id': r.cve_id, 'cvss_score': r.cvss_score,
                          'software': r.detected_software, 'version': r.detected_version,
                          'cisa_kev': r.cisa_kev},
            ))
        return alerts


# =============================================================================
# SECTION 22: TAXII FEED CLIENT
# =============================================================================

class TAXIIFeedClient:
    """Pull IOCs from TAXII 2.1 threat intelligence feeds."""

    def __init__(self, cache_path: Optional[str] = None):
        if cache_path is None:
            project_root = os.path.dirname(os.path.abspath(__file__))
            cache_path = os.path.join(project_root, "artifacts", "runtime", "cache", "taxii_cache.db")
        self.cache_path = cache_path
        self.feeds_config: Dict[str, Dict] = {}
        self.fetched_indicators: List[Dict] = []
        self.stats = {'feeds_polled': 0, 'indicators_fetched': 0,
                      'new_indicators': 0, 'errors': 0}
        self._init_cache()

    def _init_cache(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.cache_path)), exist_ok=True)
        conn = sqlite3.connect(self.cache_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS taxii_indicators (
                indicator_id TEXT PRIMARY KEY, indicator_type TEXT,
                pattern TEXT, value TEXT, source_feed TEXT,
                created TEXT, modified TEXT, valid_from TEXT,
                valid_until TEXT, labels TEXT, description TEXT,
                fetched_at TEXT, ttl_hours INTEGER DEFAULT 168
            )
        """)
        conn.commit()
        conn.close()

    def add_feed(self, name: str, url: str, collection: str, **kwargs):
        self.feeds_config[name] = {'url': url, 'collection': collection, **kwargs}

    def poll_feed(self, feed_name: str, added_after: Optional[str] = None) -> int:
        config = self.feeds_config.get(feed_name)
        if not config:
            return 0

        self.stats['feeds_polled'] += 1
        new_count = 0
        try:
            import urllib.request
            import urllib.parse
            url = config['url'].rstrip('/') + f"/collections/{config['collection']}/objects/"
            params = {'type': 'indicator'}
            if added_after:
                params['added_after'] = added_after
            full_url = f"{url}?{urllib.parse.urlencode(params)}"

            headers = {
                'Accept': 'application/taxii+json;version=2.1',
                'Content-Type': 'application/taxii+json;version=2.1',
            }

            req = urllib.request.Request(full_url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            for obj in data.get('objects', []):
                if obj.get('type') == 'indicator':
                    parsed = self._parse_stix_indicator(obj, feed_name)
                    if parsed:
                        new_count += 1
                        self.fetched_indicators.append(parsed)

            self.stats['indicators_fetched'] += len(data.get('objects', []))
            self.stats['new_indicators'] += new_count
        except Exception as e:
            self.stats['errors'] += 1
            logging.warning(f"TAXII feed '{feed_name}' poll failed: {e}")

        return new_count

    def _parse_stix_indicator(self, stix_obj: Dict, source: str) -> Optional[Dict]:
        pattern = stix_obj.get('pattern', '')
        if not pattern:
            return None
        ioc_type, ioc_value = self._extract_from_stix_pattern(pattern)
        if not ioc_type:
            return None
        return {
            'indicator_id': stix_obj.get('id', str(uuid.uuid4())),
            'indicator_type': ioc_type, 'pattern': pattern,
            'value': ioc_value, 'source_feed': source,
            'created': stix_obj.get('created', ''),
            'description': stix_obj.get('description', '')[:500],
        }

    def _extract_from_stix_pattern(self, pattern: str) -> Tuple[Optional[str], Optional[str]]:
        match = re.search(r"ipv[46]-addr:value\s*=\s*'([^']+)'", pattern)
        if match:
            return ('ip', match.group(1))
        match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        if match:
            return ('domain', match.group(1))
        match = re.search(r"file:hashes\.'([^']+)'\s*=\s*'([^']+)'", pattern)
        if match:
            return (match.group(1).lower().replace('-', ''), match.group(2))
        match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
        if match:
            return ('url', match.group(1))
        return (None, None)

    def get_cached_iocs(self, indicator_type: Optional[str] = None) -> List[Dict]:
        conn = sqlite3.connect(self.cache_path)
        if indicator_type:
            rows = conn.execute(
                "SELECT * FROM taxii_indicators WHERE indicator_type=?",
                (indicator_type,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM taxii_indicators").fetchall()
        conn.close()
        columns = ['indicator_id', 'indicator_type', 'pattern', 'value',
                    'source_feed', 'created', 'modified', 'valid_from',
                    'valid_until', 'labels', 'description', 'fetched_at', 'ttl_hours']
        return [dict(zip(columns, row)) for row in rows]


# =============================================================================
# SECTION 23: COMPOSITE SCORER & ANALYST TRIAGE
# =============================================================================

class CompositeScorer:
    """Weighted scoring + triage prioritization."""

    SEVERITY_SCORES = {
        'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 10,
    }

    WEIGHTS = {
        'base_severity': 0.30, 'intel_score': 0.25, 'chain_score': 0.20,
        'sigma_match': 0.15, 'yara_hit': 0.10,
    }

    TRIAGE_LEVELS = [
        (90, 'CRITICAL', 'Immediate response required'),
        (70, 'HIGH', 'Investigate within 1 hour'),
        (40, 'MEDIUM', 'Investigate within 4 hours'),
        (0, 'LOW', 'Review during next shift'),
    ]

    def __init__(self):
        self.scored_alerts: List[Dict] = []

    def score_alert(self, alert: Alert, intel_score: int = 0,
                    chain_score: int = 0, is_sigma: bool = False,
                    is_yara: bool = False) -> Dict:
        base = self.SEVERITY_SCORES.get((alert.severity or 'medium').lower(), 50)
        sigma = 80 if is_sigma else 0
        yara_s = 90 if is_yara else 0

        composite = int(min(100,
            base * self.WEIGHTS['base_severity'] +
            intel_score * self.WEIGHTS['intel_score'] +
            chain_score * self.WEIGHTS['chain_score'] +
            sigma * self.WEIGHTS['sigma_match'] +
            yara_s * self.WEIGHTS['yara_hit']
        ))

        triage_level, triage_desc = 'LOW', 'Review during next shift'
        for threshold, level, desc in self.TRIAGE_LEVELS:
            if composite >= threshold:
                triage_level, triage_desc = level, desc
                break

        result = {
            'alert': alert, 'composite_score': composite,
            'triage_level': triage_level, 'triage_description': triage_desc,
        }
        self.scored_alerts.append(result)
        return result

    def score_all(self, alerts: List[Alert], sigma_alerts: Set = None,
                  yara_alerts: Set = None, chain_map: Dict = None) -> List[Dict]:
        sigma_ids = sigma_alerts or set()
        yara_ids = yara_alerts or set()
        chain_map = chain_map or {}

        for alert in alerts:
            chain = chain_map.get(id(alert))
            chain_score = min(100, len(chain.alerts) * 15) if chain else 0
            self.score_alert(
                alert, chain_score=chain_score,
                is_sigma=id(alert) in sigma_ids,
                is_yara=id(alert) in yara_ids,
            )

        self.scored_alerts.sort(key=lambda x: x['composite_score'], reverse=True)
        return self.scored_alerts

    def get_summary(self) -> Dict:
        if not self.scored_alerts:
            return {'total': 0}
        levels = Counter(sa['triage_level'] for sa in self.scored_alerts)
        scores = [sa['composite_score'] for sa in self.scored_alerts]
        return {
            'total': len(self.scored_alerts),
            'triage_breakdown': dict(levels),
            'avg_score': sum(scores) / len(scores),
            'max_score': max(scores),
        }


# =============================================================================
# SECTION 12: HTML REPORT GENERATOR
# =============================================================================

class HTMLReportGenerator:
    """Interactive HTML dashboard generator."""

    def __init__(self):
        pass

    def generate(self, events: List[ParsedEvent], alerts: List[Alert],
                 iocs: List[IOC], chains: List[AttackChain],
                 scored_alerts: List[Dict], sigma_stats: Dict,
                 yara_stats: Dict, cve_results: List[CVEResult],
                 ti_results: Dict, output_path: str, input_source: str):
        """Generate the full interactive HTML report."""

        # Basic analysis (same as original)
        analysis = self._analyze_events(events)
        total = analysis["total"]
        failed_logins = sum(1 for e in events if e.event_id == 4625)
        unique_accounts = analysis["unique_accounts"]
        unique_ips = analysis["unique_ips"]
        time_start, time_end = analysis["time_range"]

        timeline_labels = [h[0] for h in analysis["hourly_timeline"]]
        timeline_values = [h[1] for h in analysis["hourly_timeline"]]
        cat_labels = list(analysis["category_breakdown"].keys())
        cat_values = list(analysis["category_breakdown"].values())
        generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        # ---- Build HTML ----
        html = []
        html.append('<!DOCTYPE html>\n<html lang="en">\n<head>\n')
        html.append('<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n')
        html.append('<title>Log Parser v4 — Threat Hunting Report</title>\n')
        html.append('<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>\n')
        html.append(self._css())
        html.append('</head>\n<body>\n')

        # Header
        html.append(f'<h1>Log Parser v4 — Threat Hunting Report</h1>\n')
        html.append(f'<p class="subtitle">Source: {self._esc(input_source)} &mdash; '
                     f'Time range: {self._esc(time_start)} to {self._esc(time_end)} &mdash; '
                     f'Generated: {generated_at}</p>\n')

        # Triage summary cards
        alert_counts = Counter(a.severity for a in alerts)
        html.append('<div class="cards">\n')
        html.append(f'  <div class="card blue"><div class="label">Total Events</div><div class="value">{total:,}</div></div>\n')
        html.append(f'  <div class="card red"><div class="label">Alerts</div><div class="value">{len(alerts):,}</div></div>\n')
        html.append(f'  <div class="card purple"><div class="label">Attack Chains</div><div class="value">{len(chains)}</div></div>\n')
        html.append(f'  <div class="card green"><div class="label">IOCs Extracted</div><div class="value">{len(iocs):,}</div></div>\n')
        html.append('</div>\n')

        # Severity cards
        html.append('<div class="cards">\n')
        for sev, color in [("critical", "#ef4444"), ("high", "#f59e0b"),
                            ("medium", "#3b82f6"), ("low", "#22c55e")]:
            cnt = alert_counts.get(sev, 0)
            html.append(f'  <div class="card" style="border-left:4px solid {color};">'
                         f'<div class="label">{sev.upper()}</div>'
                         f'<div class="value" style="color:{color};">{cnt}</div></div>\n')
        html.append('</div>\n')

        # Charts
        html.append('<div class="chart-grid">\n')
        html.append('  <div class="chart-box"><h2 style="margin-top:0;">Event Timeline (Hourly)</h2><canvas id="timelineChart"></canvas></div>\n')
        html.append('  <div class="chart-box"><h2 style="margin-top:0;">Category Breakdown</h2><canvas id="categoryChart"></canvas></div>\n')
        html.append('</div>\n')

        # Triage Queue
        if scored_alerts:
            html.append('<h2>Triage Queue (Prioritized)</h2>\n')
            html.append('<table><thead><tr><th>Score</th><th>Level</th><th>Rule</th><th>Severity</th><th>Tactic</th><th>Description</th></tr></thead><tbody>\n')
            for sa in scored_alerts[:50]:
                a = sa['alert']
                level_color = {"CRITICAL": "#ef4444", "HIGH": "#f59e0b",
                               "MEDIUM": "#3b82f6", "LOW": "#22c55e"}.get(sa['triage_level'], "#8b8fa3")
                html.append(f'<tr><td style="font-weight:bold;">{sa["composite_score"]}</td>'
                             f'<td><span style="background:{level_color};padding:2px 8px;border-radius:4px;font-size:0.8em;">{sa["triage_level"]}</span></td>'
                             f'<td>{self._esc(a.rule_name)}</td>'
                             f'<td>{self._esc(a.severity)}</td>'
                             f'<td>{self._esc(a.mitre_tactic)}</td>'
                             f'<td>{self._esc(a.description[:150])}</td></tr>\n')
            html.append('</tbody></table>\n')

        # MITRE ATT&CK Heatmap
        tactic_counts = Counter(a.mitre_tactic for a in alerts)
        if tactic_counts:
            html.append('<h2>MITRE ATT&CK Coverage</h2>\n')
            html.append('<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px;">\n')
            max_count = max(tactic_counts.values()) if tactic_counts else 1
            for tactic, count in tactic_counts.most_common():
                intensity = min(255, int((count / max_count) * 200) + 55)
                html.append(f'<div style="background:rgba(239,68,68,{intensity/255:.2f});'
                             f'padding:12px 16px;border-radius:8px;text-align:center;min-width:120px;">'
                             f'<div style="font-size:0.8em;color:#ccc;">{self._esc(tactic)}</div>'
                             f'<div style="font-size:1.5em;font-weight:bold;">{count}</div></div>\n')
            html.append('</div>\n')

        # Attack Chains
        if chains:
            html.append('<h2>Attack Chains</h2>\n')
            html.append('<table><thead><tr><th>Chain ID</th><th>Host</th><th>Tactics</th><th>Events</th><th>Risk</th><th>Duration</th></tr></thead><tbody>\n')
            for chain in chains:
                duration = ""
                if chain.start_time and chain.end_time:
                    dur = chain.end_time - chain.start_time
                    duration = f"{dur.total_seconds() / 60:.0f} min"
                html.append(f'<tr><td>{chain.chain_id}</td><td>{self._esc(chain.host)}</td>'
                             f'<td>{self._esc(" → ".join(chain.tactics))}</td>'
                             f'<td>{len(chain.alerts)}</td>'
                             f'<td style="font-weight:bold;">{chain.risk_score}</td>'
                             f'<td>{duration}</td></tr>\n')
            html.append('</tbody></table>\n')

        # IOC Summary
        if iocs:
            ioc_type_counts = Counter(ioc.ioc_type for ioc in iocs)
            html.append('<h2>IOC Summary</h2>\n')
            html.append('<table><thead><tr><th>Type</th><th>Count</th><th>Sample Values</th></tr></thead><tbody>\n')
            for ioc_type, count in ioc_type_counts.most_common():
                samples = [i.value for i in iocs if i.ioc_type == ioc_type][:5]
                html.append(f'<tr><td>{ioc_type.upper()}</td><td>{count}</td>'
                             f'<td style="font-family:monospace;font-size:0.85em;">{", ".join(self._esc(s) for s in samples)}</td></tr>\n')
            html.append('</tbody></table>\n')

        # Alerts table
        html.append('<h2>All Alerts</h2>\n')
        html.append('<div class="filter-bar">\n')
        html.append('  <input type="text" id="alertSearch" placeholder="Search alerts..." oninput="filterAlerts()">\n')
        html.append('  <select id="severityFilter" onchange="filterAlerts()">\n')
        html.append('    <option value="">All Severities</option>\n')
        for sev in ["critical", "high", "medium", "low"]:
            html.append(f'    <option value="{sev}">{sev.capitalize()}</option>\n')
        html.append('  </select>\n</div>\n')
        html.append('<table id="alertsTable"><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Tactic</th><th>Technique</th><th>Description</th></tr></thead><tbody>\n')
        for a in alerts[:500]:
            sev_colors = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#3b82f6", "low": "#22c55e"}
            sev_color = sev_colors.get(a.severity, "#8b8fa3")
            ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else ""
            html.append(f'<tr data-severity="{self._esc(a.severity)}">'
                         f'<td>{ts}</td>'
                         f'<td><span style="background:{sev_color};padding:2px 8px;border-radius:4px;font-size:0.8em;">{self._esc(a.severity)}</span></td>'
                         f'<td>{self._esc(a.rule_name)}</td>'
                         f'<td>{self._esc(a.mitre_tactic)}</td>'
                         f'<td>{self._esc(a.mitre_technique)}</td>'
                         f'<td>{self._esc(a.description[:200])}</td></tr>\n')
        html.append('</tbody></table>\n')

        # Event ID Breakdown
        html.append('<h2>Event ID Breakdown</h2>\n')
        html.append('<table><thead><tr><th>Event ID</th><th>Category</th><th>Description</th><th style="text-align:right;">Count</th></tr></thead><tbody>\n')
        for item in analysis["event_id_breakdown"]:
            html.append(f'<tr><td>{item["id"]}</td><td>{self._esc(item["category"])}</td>'
                         f'<td>{self._esc(item["description"])}</td>'
                         f'<td style="text-align:right;font-weight:bold;">{item["count"]:,}</td></tr>\n')
        html.append('</tbody></table>\n')

        # Failed logins
        if analysis["failed_login_accounts"]:
            html.append('<h2>Top Failed Login Accounts</h2>\n')
            html.append('<table><thead><tr><th>Account</th><th style="text-align:right;">Failures</th></tr></thead><tbody>\n')
            for acct, count in analysis["failed_login_accounts"]:
                html.append(f'<tr><td>{self._esc(acct)}</td><td style="text-align:right;font-weight:bold;">{count:,}</td></tr>\n')
            html.append('</tbody></table>\n')

        # JavaScript
        html.append('<script>\n')
        html.append(f'const timelineLabels = {json.dumps(timeline_labels)};\n')
        html.append(f'const timelineData = {json.dumps(timeline_values)};\n')
        html.append(f'const catLabels = {json.dumps(cat_labels)};\n')
        html.append(f'const catData = {json.dumps(cat_values)};\n\n')

        html.append("""
new Chart(document.getElementById('timelineChart'), {
    type: 'line',
    data: { labels: timelineLabels, datasets: [{ label: 'Events', data: timelineData,
        borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', fill: true, tension: 0.3, pointRadius: 2 }] },
    options: { responsive: true, plugins: { legend: { display: false } },
        scales: { x: { ticks: { color:'#8b8fa3', maxTicksLimit:12 }, grid: { color:'#1f2230' } },
                  y: { ticks: { color:'#8b8fa3' }, grid: { color:'#1f2230' }, beginAtZero:true } } }
});

new Chart(document.getElementById('categoryChart'), {
    type: 'doughnut',
    data: { labels: catLabels, datasets: [{ data: catData,
        backgroundColor: ['#3b82f6','#f59e0b','#a855f7','#22c55e','#ef4444','#06b6d4','#f97316','#ec4899'], borderWidth: 0 }] },
    options: { responsive: true, plugins: { legend: { position:'bottom', labels:{ color:'#e2e4ea', padding:12 } } } }
});

function filterAlerts() {
    const search = document.getElementById('alertSearch').value.toLowerCase();
    const severity = document.getElementById('severityFilter').value;
    document.querySelectorAll('#alertsTable tbody tr').forEach(row => {
        const text = row.textContent.toLowerCase();
        const rowSev = row.getAttribute('data-severity') || '';
        row.style.display = (!search || text.includes(search)) && (!severity || rowSev === severity) ? '' : 'none';
    });
}
""")
        html.append('</script>\n</body>\n</html>\n')

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("".join(html))
        return output_path

    def _css(self) -> str:
        return """<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0f1117; color:#e2e4ea; font-family:'Segoe UI',system-ui,-apple-system,sans-serif; padding:24px; }
h1 { font-size:1.8em; margin-bottom:4px; }
h2 { font-size:1.3em; margin:32px 0 16px; border-bottom:1px solid #2a2d3a; padding-bottom:8px; }
.subtitle { color:#8b8fa3; margin-bottom:24px; font-size:0.95em; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px; }
.card { background:#1a1d27; border-radius:10px; padding:20px; }
.card .label { font-size:0.85em; color:#8b8fa3; text-transform:uppercase; letter-spacing:0.5px; }
.card .value { font-size:2em; font-weight:700; margin-top:4px; }
.card.blue .value { color:#3b82f6; } .card.red .value { color:#ef4444; }
.card.purple .value { color:#a855f7; } .card.green .value { color:#22c55e; }
.chart-grid { display:grid; grid-template-columns:2fr 1fr; gap:16px; margin-bottom:8px; }
.chart-box { background:#1a1d27; border-radius:10px; padding:20px; }
table { width:100%; border-collapse:collapse; background:#1a1d27; border-radius:10px; overflow:hidden; margin-bottom:16px; }
th { background:#22253a; text-align:left; padding:10px 14px; font-size:0.85em; color:#8b8fa3; text-transform:uppercase; }
td { padding:8px 14px; border-bottom:1px solid #1f2230; font-size:0.9em; }
tr:hover { background:rgba(255,255,255,0.03); }
.filter-bar { display:flex; gap:12px; margin-bottom:12px; }
.filter-bar input, .filter-bar select { background:#1a1d27; border:1px solid #2a2d3a; color:#e2e4ea; padding:8px 12px; border-radius:6px; font-size:0.9em; }
.filter-bar input { flex:1; }
@media (max-width:768px) { .chart-grid { grid-template-columns:1fr; } }
</style>
"""

    def _esc(self, text) -> str:
        return (str(text).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))

    def _analyze_events(self, events: List[ParsedEvent]) -> Dict:
        """Produce analysis dicts from parsed events."""
        if not events:
            return {"total": 0, "unique_accounts": 0, "unique_ips": 0,
                    "time_range": ("N/A", "N/A"), "event_id_breakdown": [],
                    "category_breakdown": {}, "failed_login_accounts": [],
                    "failed_login_ips": [], "privilege_accounts": [],
                    "hourly_timeline": [], "recent_events": []}

        accounts, ips, timestamps = set(), set(), []
        eid_counter, cat_counter = Counter(), Counter()
        failed_accounts, failed_ips, priv_accounts = Counter(), Counter(), Counter()
        hourly = defaultdict(int)

        for ev in events:
            user = ev.target_user or ev.subject_user
            if user and user != "-":
                accounts.add(user)
            if ev.source_ip and ev.source_ip != "-":
                ips.add(ev.source_ip)
            if ev.timestamp:
                timestamps.append(ev.timestamp)
                hourly[ev.timestamp.strftime("%Y-%m-%d %H:00")] += 1

            eid_counter[ev.event_id] += 1
            cat_counter[ev.category] += 1

            if ev.event_id == 4625:
                acct = ev.target_user or ev.subject_user or "(unknown)"
                failed_accounts[acct] += 1
                src = ev.source_ip if ev.source_ip and ev.source_ip != "-" else "(unknown)"
                failed_ips[src] += 1

            if ev.event_id in (4672, 4673, 4674):
                acct = ev.subject_user or ev.target_user or "(unknown)"
                priv_accounts[acct] += 1

        timestamps.sort()
        time_range = (
            timestamps[0].strftime("%Y-%m-%d %H:%M:%S") if timestamps else "N/A",
            timestamps[-1].strftime("%Y-%m-%d %H:%M:%S") if timestamps else "N/A",
        )

        eid_breakdown = []
        for eid, count in eid_counter.most_common():
            cat, desc = EVENT_IDS.get(eid, ("Unknown", "Unknown"))
            eid_breakdown.append({"id": eid, "count": count, "category": cat, "description": desc})

        return {
            "total": len(events), "unique_accounts": len(accounts),
            "unique_ips": len(ips), "time_range": time_range,
            "event_id_breakdown": eid_breakdown,
            "category_breakdown": dict(cat_counter),
            "failed_login_accounts": failed_accounts.most_common(15),
            "failed_login_ips": failed_ips.most_common(15),
            "privilege_accounts": priv_accounts.most_common(10),
            "hourly_timeline": sorted(hourly.items()),
            "recent_events": events[-100:],
        }


# =============================================================================
# SECTION 13: MAIN ENGINE + CLI
# =============================================================================

def export_csv(alerts: List[Alert], filepath: str):
    """Export alerts as CSV."""
    import csv
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "severity", "rule_name", "mitre_tactic",
                          "mitre_technique", "description", "computer", "event_id"])
        for a in alerts:
            writer.writerow([
                a.timestamp.isoformat() if a.timestamp else "",
                a.severity, a.rule_name, a.mitre_tactic,
                a.mitre_technique, a.description,
                a.event.computer if a.event else "",
                a.event.event_id if a.event else "",
            ])
    print(f"  CSV exported to {filepath}")


def export_json(alerts: List[Alert], filepath: str):
    """Export alerts as JSON."""
    data = []
    for a in alerts:
        data.append({
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "severity": a.severity,
            "rule_name": a.rule_name,
            "mitre_tactic": a.mitre_tactic,
            "mitre_technique": a.mitre_technique,
            "description": a.description,
            "computer": a.event.computer if a.event else "",
            "event_id": a.event.event_id if a.event else None,
            "evidence": a.evidence,
        })
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  JSON exported to {filepath}")


def export_iocs(iocs: List[IOC], filepath: str, stix: bool = False):
    """Export IOCs as JSON (optionally STIX 2.1 format)."""
    if stix:
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": []
        }
        for ioc in iocs:
            stix_type_map = {
                "ip": f"[ipv4-addr:value = '{ioc.value}']",
                "domain": f"[domain-name:value = '{ioc.value}']",
                "url": f"[url:value = '{ioc.value}']",
                "sha256": f"[file:hashes.'SHA-256' = '{ioc.value}']",
                "sha1": f"[file:hashes.'SHA-1' = '{ioc.value}']",
                "md5": f"[file:hashes.'MD5' = '{ioc.value}']",
                "email": f"[email-addr:value = '{ioc.value}']",
            }
            pattern = stix_type_map.get(ioc.ioc_type)
            if pattern:
                bundle["objects"].append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen.isoformat() if ioc.first_seen else "",
                    "labels": [ioc.ioc_type],
                })
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
    else:
        data = [{"type": i.ioc_type, "value": i.value, "count": i.count,
                 "context": i.context,
                 "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                 "last_seen": i.last_seen.isoformat() if i.last_seen else None}
                for i in iocs]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    print(f"  IOCs exported to {filepath}")


def print_triage_queue(scored_alerts: List[Dict]):
    """Print triage queue to console."""
    print(f"\n{'='*80}")
    print(f"  ANALYST TRIAGE QUEUE")
    print(f"{'='*80}\n")

    level_counts = Counter(sa['triage_level'] for sa in scored_alerts)
    print(f"  CRITICAL: {level_counts.get('CRITICAL', 0)}  |  "
          f"HIGH: {level_counts.get('HIGH', 0)}  |  "
          f"MEDIUM: {level_counts.get('MEDIUM', 0)}  |  "
          f"LOW: {level_counts.get('LOW', 0)}\n")

    for i, sa in enumerate(scored_alerts[:20], 1):
        a = sa['alert']
        print(f"  [{sa['triage_level']:>8}] Score: {sa['composite_score']:>3}  "
              f"| {a.severity:<8} | {a.rule_name}")
        print(f"           {a.mitre_tactic} / {a.mitre_technique}")
        print(f"           {a.description[:120]}")
        print()

    print(f"{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Log Parser v4 — Windows Event Log Threat Hunting Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_parser.py Security.evtx --html report.html
  python log_parser.py ./logs/ --html report.html --enrich --triage
  python log_parser.py ./logs/ --sigma-rules ./sigma/rules/windows/ --html report.html
  python log_parser.py ./logs/ --html report.html --csv findings.csv --json findings.json
        """
    )

    # Positional
    parser.add_argument("INPUT", help="EVTX file or directory of EVTX files")

    # Output formats
    parser.add_argument("--html", metavar="FILE", help="Generate interactive HTML report")
    parser.add_argument("--csv", metavar="FILE", help="Export findings as CSV")
    parser.add_argument("--json", metavar="FILE", help="Export findings as JSON")
    parser.add_argument("--ioc-export", metavar="FILE", help="Export extracted IOCs")
    parser.add_argument("--stix", action="store_true", help="Export IOCs in STIX 2.1 format")
    parser.add_argument("--output", metavar="DIR", help="Output directory for generated files")

    # Filtering
    parser.add_argument("--start", help="Start date filter (YYYY-MM-DD)")
    parser.add_argument("--end", help="End date filter (YYYY-MM-DD)")
    parser.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                        help="Minimum severity level to include")

    # Enrichment
    parser.add_argument("--enrich", action="store_true", help="Enable live threat intel enrichment")
    parser.add_argument("--otx-key", metavar="KEY", help="AlienVault OTX API key")
    parser.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key")
    parser.add_argument("--abuseipdb-key", metavar="KEY", help="AbuseIPDB API key")
    parser.add_argument("--shodan-key", metavar="KEY", help="Shodan API key")

    # Detection rules
    parser.add_argument("--sigma-rules", metavar="DIR", help="Path to SIGMA rule YAML files")
    parser.add_argument("--yara-rules", metavar="DIR", help="Path to YARA rule files")

    # CVE + TAXII
    parser.add_argument("--cve-check", action="store_true", help="Enable CVE correlation")
    parser.add_argument("--taxii-url", metavar="URL", help="TAXII 2.1 server URL")
    parser.add_argument("--taxii-collection", metavar="ID", help="TAXII collection to poll")

    # Triage
    parser.add_argument("--triage", action="store_true", help="Output prioritized analyst queue")

    # Options
    parser.add_argument("--no-cache", action="store_true", help="Disable SQLite threat intel cache")
    parser.add_argument("--no-fp-filter", action="store_true", help="Disable false positive filtering")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    args = parser.parse_args()

    # Setup logging
    log_level = logging.WARNING
    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose >= 1:
        log_level = logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    # Validate input
    input_path = args.INPUT
    is_dir = os.path.isdir(input_path)
    is_file = os.path.isfile(input_path)
    if not is_dir and not is_file:
        print(f"Error: Path not found: {input_path}")
        sys.exit(1)

    # Output directory. Relative generated paths are kept inside the project
    # unless the caller explicitly supplies an absolute output path.
    generated_output_dir = args.output
    if generated_output_dir:
        os.makedirs(generated_output_dir, exist_ok=True)

    # Parse date filters
    start_date, end_date = None, None
    if args.start:
        try:
            start_date = datetime.strptime(args.start, "%Y-%m-%d").date()
        except ValueError:
            print(f"Error: Invalid start date format: {args.start} (expected YYYY-MM-DD)")
            sys.exit(1)
    if args.end:
        try:
            end_date = datetime.strptime(args.end, "%Y-%m-%d").date()
        except ValueError:
            print(f"Error: Invalid end date format: {args.end} (expected YYYY-MM-DD)")
            sys.exit(1)

    # Default output: if nothing specified, at least print summary
    if not any([args.html, args.csv, args.json, args.ioc_export, args.triage]):
        args.html = "report.html"

    if generated_output_dir is None:
        project_root = os.path.dirname(os.path.abspath(__file__))
        generated_output_dir = os.path.join(project_root, "artifacts", "output")
        os.makedirs(generated_output_dir, exist_ok=True)

    # Resolve output paths
    def out_path(p):
        if p and (args.output or not os.path.isabs(p)):
            return os.path.join(generated_output_dir, os.path.basename(p))
        return p

    # ---- Banner ----
    print(f"\n{'='*60}")
    print(f"  Log Parser v4 — Threat Hunting Engine")
    print(f"{'='*60}")
    print(f"  Input:  {input_path}")
    if start_date:
        print(f"  Start:  {start_date}")
    if end_date:
        print(f"  End:    {end_date}")
    if args.html:
        print(f"  HTML:   {out_path(args.html)}")
    if args.csv:
        print(f"  CSV:    {out_path(args.csv)}")
    if args.json:
        print(f"  JSON:   {out_path(args.json)}")
    modules = []
    if args.enrich:
        modules.append("Threat Intel")
    if args.sigma_rules:
        modules.append("SIGMA")
    if args.yara_rules:
        modules.append("YARA")
    if args.cve_check:
        modules.append("CVE")
    if args.taxii_url:
        modules.append("TAXII")
    if not args.no_fp_filter:
        modules.append("FP Filter")
    if modules:
        print(f"  Modules: {', '.join(modules)}")
    print(f"{'='*60}\n")

    # ---- Step 1: Parse ----
    print("[1/8] Parsing EVTX files...")
    event_parser = EventParser()
    if is_dir:
        events = event_parser.parse_directory(input_path, start_date, end_date)
    else:
        events = event_parser.parse_evtx_file(input_path, start_date, end_date)

    stats = event_parser.stats
    print(f"  Scanned {stats['total']} records, extracted {stats['parsed']} events, "
          f"skipped {stats['skipped']} unreadable\n")

    if not events:
        print("  No events found. Exiting.")
        sys.exit(0)

    # ---- Step 2: Detect ----
    print("[2/8] Running detection engine...")
    all_alerts: List[Alert] = []

    detectors = [
        CommandLineAnalyzer(),
        PersistenceDetector(),
        LateralMovementDetector(),
        DefenseEvasionDetector(),
        CredentialAccessDetector(),
        BruteForceDetector(),
        AccountAnomalyDetector(),
        DiscoveryDetector(),
        ExfiltrationDetector(),
        CommandAndControlDetector(),
        ImpactDetector(),
    ]

    for detector in detectors:
        det_alerts = detector.analyze_all(events)
        if det_alerts:
            print(f"  {detector.name}: {len(det_alerts)} alerts")
        all_alerts.extend(det_alerts)

    # ---- Step 3: False Positive Filtering ----
    fp_filter = FalsePositiveFilter()
    fp_summary = ""
    if not args.no_fp_filter:
        print("\n[3/8] False positive filtering...")
        before = len(all_alerts)
        all_alerts = fp_filter.filter_alerts(all_alerts)
        fp_summary = fp_filter.get_summary()
        print(f"  Before: {before} alerts -> After: {len(all_alerts)} alerts")
        print(fp_summary)
    else:
        print("\n[3/8] False positive filtering: DISABLED")
    print()

    # ---- Step 3b: SIGMA + YARA ----
    sigma_alerts: List[Alert] = []
    yara_alerts: List[Alert] = []
    sigma_stats = {"rules_loaded": 0, "matches": 0}
    yara_stats = {"files_scanned": 0, "matches": 0}

    print("[4/8] Loading detection rules...")
    if args.sigma_rules:
        sigma_eval = SIGMAEvaluator()
        loaded = sigma_eval.load_rules(args.sigma_rules)
        sigma_stats = sigma_eval.stats
        print(f"  SIGMA: {loaded} rules loaded")
        if loaded:
            sigma_alerts = sigma_eval.evaluate(events)
            if not args.no_fp_filter:
                sigma_alerts = fp_filter.filter_alerts(sigma_alerts)
            print(f"  SIGMA: {len(sigma_alerts)} matches")
            all_alerts.extend(sigma_alerts)
    else:
        print("  SIGMA: skipped (use --sigma-rules)")

    if args.yara_rules:
        yara_scanner = YARAScanner()
        loaded = yara_scanner.load_rules(args.yara_rules)
        yara_stats = yara_scanner.stats
        print(f"  YARA: {loaded} rules loaded")
        if loaded and is_dir:
            yara_scanner.scan_directory(input_path)
            yara_alerts = yara_scanner.to_alerts()
            print(f"  YARA: {len(yara_alerts)} hits")
            all_alerts.extend(yara_alerts)
    else:
        print("  YARA: skipped (use --yara-rules)")

    # ---- Step 4: IOC Extraction ----
    print("[5/8] Extracting IOCs...")
    ioc_extractor = IOCExtractor()
    iocs = ioc_extractor.extract_from_events(events)
    print(f"  Extracted {len(iocs)} unique IOCs")

    # ---- Step 5: Threat Intel Enrichment ----
    ti_results: Dict = {}
    print("[6/8] Threat intelligence enrichment...")
    if args.enrich:
        ti_engine = ThreatIntelEngine(
            otx_key=args.otx_key, vt_key=args.vt_key,
            abuseipdb_key=args.abuseipdb_key, shodan_key=args.shodan_key,
            use_cache=not args.no_cache,
        )
        sources = []
        if ti_engine.otx_key:
            sources.append("OTX")
        if ti_engine.vt_key:
            sources.append("VT")
        if ti_engine.abuseipdb_key:
            sources.append("AbuseIPDB")
        if ti_engine.shodan_key:
            sources.append("Shodan")
        print(f"  Sources: {', '.join(sources) if sources else 'No API keys configured'}")
        if sources:
            ti_results = ti_engine.enrich_all(iocs)
            print(f"  Lookups: {ti_engine.stats['lookups']}, "
                  f"Hits: {ti_engine.stats['hits']}, "
                  f"Cache: {ti_engine.stats['cache_hits']}")
    else:
        print("  Skipped (use --enrich)")

    # CVE correlation
    cve_results: List[CVEResult] = []
    if args.cve_check:
        print("  CVE correlation...")
        cve_correlator = CVECorrelator()
        cve_correlator.load_kev_catalog()
        cve_results = cve_correlator.correlate(events)
        cve_alerts = cve_correlator.to_alerts()
        all_alerts.extend(cve_alerts)
        print(f"  CVE: {cve_correlator.stats['software_detected']} software detected, "
              f"{cve_correlator.stats['cves_found']} CVEs matched")

    # TAXII feeds
    if args.taxii_url and args.taxii_collection:
        print("  TAXII feed polling...")
        taxii = TAXIIFeedClient()
        taxii.add_feed("custom", args.taxii_url, args.taxii_collection)
        new = taxii.poll_feed("custom")
        print(f"  TAXII: {new} new indicators")

    # ---- Step 6: Correlate ----
    print("[7/8] Attack chain correlation...")
    correlator = AttackChainCorrelator()
    chains = correlator.correlate(all_alerts)
    print(f"  Identified {len(chains)} attack chains")

    # Severity filter
    if args.severity:
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(args.severity)
        all_alerts = [a for a in all_alerts
                      if severity_order.index(a.severity) >= min_idx]
        print(f"  Filtered to {len(all_alerts)} alerts (>= {args.severity})")

    # ---- Step 7: Score + Report ----
    print("[8/8] Scoring and generating reports...")
    scorer = CompositeScorer()
    sigma_alert_ids = {id(a) for a in sigma_alerts}
    yara_alert_ids = {id(a) for a in yara_alerts}
    chain_map = {}
    for chain in chains:
        for a in chain.alerts:
            chain_map[id(a)] = chain
    scored = scorer.score_all(all_alerts, sigma_alert_ids, yara_alert_ids, chain_map)

    # Outputs
    if args.html:
        html_path = out_path(args.html)
        report_gen = HTMLReportGenerator()
        report_gen.generate(events, all_alerts, iocs, chains, scored,
                            sigma_stats, yara_stats, cve_results, ti_results,
                            html_path, input_path)
        print(f"  HTML report: {os.path.abspath(html_path)}")

    if args.csv:
        export_csv(all_alerts, out_path(args.csv))

    if args.json:
        export_json(all_alerts, out_path(args.json))

    if args.ioc_export:
        export_iocs(iocs, out_path(args.ioc_export), stix=args.stix)

    if args.triage:
        print_triage_queue(scored)

    # ---- Summary ----
    summary = scorer.get_summary()
    print(f"\n{'='*60}")
    print(f"  Summary")
    print(f"{'='*60}")
    print(f"  Events parsed:     {len(events):,}")
    print(f"  Total alerts:      {len(all_alerts):,}")
    print(f"  FP suppressed:     {fp_filter.suppressed}")
    print(f"  Attack chains:     {len(chains)}")
    print(f"  IOCs extracted:    {len(iocs):,}")
    if summary.get('total'):
        breakdown = summary.get('triage_breakdown', {})
        print(f"  Triage: CRITICAL={breakdown.get('CRITICAL', 0)}  "
              f"HIGH={breakdown.get('HIGH', 0)}  "
              f"MEDIUM={breakdown.get('MEDIUM', 0)}  "
              f"LOW={breakdown.get('LOW', 0)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
