"""Persistence detection rules with analyst guidance."""

import html
import os
import re
from datetime import timedelta
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse
from models.event_model import NormalizedEvent, Alert

URL_RE = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)


BENIGN_SERVICE_NAMES = {
    "wuauserv",
    "bits",
    "trustedinstaller",
    "windows update",
    "rdagent",
    "windows azure guest agent",
    "mellanox winof-2 networking driver",
}

BENIGN_SERVICE_PATH_MARKERS = (
    "\\windowsazure\\packages\\waappagent.exe",
    "\\system32\\drivers\\mlx5.sys",
)
SUSPICIOUS_TASK_MARKERS = (
    "powershell",
    "pwsh",
    "cmd.exe",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "bitsadmin",
    "frombase64string",
    "encodedcommand",
    "\\\\127.0.0.1\\admin$",
    "\\\\localhost\\admin$",
)
SUSPICIOUS_SERVICE_EXECUTION_MARKERS = (
    "%comspec%",
    "%temp%\\execute.bat",
    "__output",
    "cmd.exe",
    "powershell",
    "pwsh",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "\\\\127.0.0.1\\admin$",
    "\\\\localhost\\admin$",
    "\\users\\",
    "\\programdata\\",
    "\\temp\\",
)

USER_CONTROLLED_PATH_MARKERS = (
    "\\users\\",
    "\\programdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "/users/",
    "/programdata/",
    "/temp/",
    "/tmp/",
)
BENIGN_BITS_JOB_NAMES = {
    "font download",
    "presigninsettingsconfigjson",
    "push notification platform job: 1",
    "updatedescriptionxml",
    "chrome component updater",
}
BENIGN_BITS_PROCESS_MARKERS = (
    "\\google\\update\\googleupdate.exe",
    "\\microsoft\\onedrive\\onedrivestandaloneupdater.exe",
    "\\windows\\system32\\svchost.exe",
)
BENIGN_BITS_REMOTE_HOSTS = {
    "clients2.google.com",
    "fs.microsoft.com",
    "g.live.com",
    "img-s-msn-com.akamaized.net",
    "oneclient.sfx.ms",
    "site-cdn.onenote.net",
    "storage.googleapis.com",
}
BENIGN_BITS_REMOTE_HOST_SUFFIXES = (".gvt1.com",)
BENIGN_BITS_REMOTE_PATH_MARKERS = (
    "/edgedl/release2/",
    "/service/check2",
    "/update-delta/",
    "/odclientsettings/prod",
    "/1rewlive5skydrive/odsuproduction",
    "/fs/windows/config.json",
    "/livetileimages/",
)
BITS_SUSPICIOUS_REMOTE_MARKERS = (
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".hta",
    ".js",
    ".zip",
    ".7z",
    ".cab",
    "openvpn",
    "beacon",
    "backdoor",
    "payload",
    "stager",
    "mimikatz",
)
BITS_BENIGN_UPDATER_NAME_MARKERS = (
    "googleupdatesetup",
    "chrome_updater",
    ".crx3",
    ".crxd",
)
LOCAL_SAM_NAMES_PREFIX = "hklm\\sam\\sam\\domains\\account\\users\\names\\"
LOCAL_ADMIN_ALIAS_KEY = r"hklm\sam\sam\domains\builtin\aliases\00000220\c"
SPECIAL_ACCOUNTS_USERLIST_PREFIX = r"hklm\software\microsoft\windows nt\currentversion\winlogon\specialaccounts\userlist\\"
LANMANSERVER_SHARES_PREFIX = "hklm\\system\\currentcontrolset\\services\\lanmanserver\\shares\\"
WELL_KNOWN_MEMBER_SIDS = {
    "s-1-5-18": "NT AUTHORITY\\SYSTEM",
    "s-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "s-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
}
WMI_ACTIVITY_SUBSCRIPTION_MARKERS = (
    "__eventfilter",
    "__filtertoconsumerbinding",
    "__eventconsumer",
    "commandlineeventconsumer",
    "activescripteventconsumer",
    "nteventlogeventconsumer",
    "perm. consumer",
    "binding eventfilter",
)
ACCESSIBILITY_TRIGGER_PARENTS = {"utilman.exe", "winlogon.exe", "logonui.exe", "atbroker.exe"}
ACCESSIBILITY_BINARIES = {"utilman.exe", "osk.exe", "sethc.exe", "narrator.exe", "magnify.exe", "atbroker.exe"}
ACCESSIBILITY_FOLLOW_ON = {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe"}
SENSITIVE_GROUP_NAMES = (
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "backup operators",
    "account operators",
    "server operators",
    "dnsadmins",
)
WELL_KNOWN_GROUP_SIDS = {
    "s-1-5-32-544": "Administrators",
    "s-1-5-32-545": "Users",
    "s-1-5-32-548": "Account Operators",
    "s-1-5-32-549": "Server Operators",
    "s-1-5-32-551": "Backup Operators",
}
WMI_NAME_RE = re.compile(r'Name\s*=\s*"([^"]+)"', re.IGNORECASE)
WMI_CONSUMER_RE = re.compile(
    r"(CommandLineEventConsumer|ActiveScriptEventConsumer|NTEventLogEventConsumer|LogFileEventConsumer)",
    re.IGNORECASE,
)
WMI_COMMAND_RE = re.compile(r'CommandLineTemplate\s*=\s*"([^"]+)"', re.IGNORECASE)
DIRECTORY_POLICY_DN_MARKER = "cn=policies,cn=system,"
ADMINSDHOLDER_DN_MARKER = "cn=adminsdholder,cn=system,"
EXTENDED_RIGHTS_DN_MARKER = "cn=extended-rights,cn=configuration,"
GPO_SUSPICIOUS_ATTRIBUTES = {"versionnumber", "gpcfilesyspath", "gpcmachineextensionnames", "gpcuserextensionnames", "flags"}
SHADOW_CREDENTIAL_ATTRIBUTE = "msds-keycredentiallink"
DELEGATION_ATTRIBUTES = {"msds-allowedtoactonbehalfofotheridentity": "resource-based constrained delegation", "msds-allowedtodelegateto": "constrained delegation"}
ADCS_SAN_RE = re.compile(r"(?:san:|upn=|dns=)([^,;\s]+)", re.IGNORECASE)
ADCS_TEMPLATE_RISK_MARKERS = ("enrollee supplies subject", "ct_flag_enrollee_supplies_subject", "client authentication", "certificate request agent", "any purpose")
SPN_SUSPICIOUS_PREFIXES = ("http/", "mssqlsvc/", "termsrv/", "wsman/", "cifs/", "ldap/")
DEFAULT_COMPUTER_SPN_PREFIXES = ("host/", "restrictedkrbhost/")
SETSPN_ADD_RE = re.compile(
    r'\bsetspn(?:\.exe)?\s+-(?:a|s)\s+(?:"([^"]+)"|([^\s"]+))\s+(?:"([^"]+)"|([^\s"]+))',
    re.IGNORECASE,
)
ADCS_OCSP_ALLOWED_PRINCIPALS = ("builtin\\administrators", "iis apppool\\ocspisapiapppool", "cloneable domain controllers")
WMI_PERSISTENCE_EVENT_TYPES = {19: "filter", 20: "consumer", 21: "binding"}
STARTUP_TARGET_RE = re.compile(r"\\users\\([^\\]+)\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\", re.IGNORECASE)
NET_USER_ADD_RE = re.compile(r"\bnet1?\s+user\s+(?:\"([^\"]+)\"|([^\s\"&|]+)).*?/add\b", re.IGNORECASE)
USERLIST_CMD_RE = re.compile(
    r"\breg(?:\.exe)?\s+add\s+\"?(HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist)\"?.*?\s/v\s+\"?([^\s\"&|]+)\"?.*?\s/d\s+(0x0+|0)\b",
    re.IGNORECASE,
)
ACCOUNT_CONTROL_UAC_RULES = (
    {
        "title": "Sensitive and Not Delegatable Enabled",
        "phrases": ("account is sensitive and cannot be delegated", "sensitive and cannot be delegated"),
        "tokens": ("%%2094",),
        "severity": "high",
        "mitre_technique": "T1098",
        "summary": "marked the account as sensitive and not delegatable",
        "explanation": "Changing an account to Sensitive and Not Delegatable alters how Kerberos delegation works and is a notable account-control modification that can support attacker-controlled identity staging.",
        "investigate_next": "Confirm who requested the delegation restriction change, review nearby delegation-related modifications, and verify the account's intended role.",
    },
    {
        "title": "Kerberos Preauthentication Disabled",
        "phrases": ("do not require kerberos preauthentication", "does not require kerberos preauthentication"),
        "tokens": ("%%2096",),
        "severity": "critical",
        "mitre_technique": "T1098",
        "summary": "disabled Kerberos preauthentication",
        "explanation": "Disabling Kerberos preauthentication makes an account immediately eligible for AS-REP roasting and is a high-risk form of account manipulation.",
        "investigate_next": "Re-enable preauthentication unless explicitly required, review whether ticket requests followed the change, and reset the account password if abuse is suspected.",
    },
    {
        "title": "Kerberos DES-Only Encryption Enabled",
        "phrases": ("use only kerberos des encryption types", "use kerberos des encryption types for this account"),
        "tokens": ("%%2095",),
        "severity": "high",
        "mitre_technique": "T1098",
        "summary": "restricted the account to Kerberos DES encryption",
        "explanation": "Forcing DES-only Kerberos weakens ticket encryption and can make offline cracking or compatibility abuse easier for an attacker.",
        "investigate_next": "Review why DES was enabled, inspect Kerberos activity for the account, and restore stronger encryption types if the change was not approved.",
    },
    {
        "title": "Reversible Password Encryption Enabled",
        "phrases": ("store passwords using reversible encryption", "reversible password encryption"),
        "tokens": ("%%2091",),
        "severity": "critical",
        "mitre_technique": "T1098",
        "summary": "enabled reversible password encryption",
        "explanation": "Reversible password encryption materially weakens credential storage and can expose passwords in a form much closer to plaintext.",
        "investigate_next": "Determine why reversible encryption was enabled, check whether the account was used for legacy compatibility only, and rotate the password after reverting the setting.",
    },
    {
        "title": "Password Not Required Enabled",
        "phrases": ("password not required",),
        "tokens": ("%%2082",),
        "severity": "high",
        "mitre_technique": "T1098",
        "summary": "enabled the Password Not Required flag",
        "explanation": "Setting Password Not Required weakens the account's authentication requirements and can preserve access even if normal password hygiene is enforced elsewhere.",
        "investigate_next": "Validate why the account was changed to allow blank or missing passwords, review follow-on logons, and revert the flag if it was not explicitly approved.",
    },
    {
        "title": "Password Never Expires Enabled",
        "phrases": ("password never expires", "password does not expire"),
        "tokens": ("%%2089",),
        "severity": "high",
        "mitre_technique": "T1098",
        "summary": "enabled the Password Never Expires flag",
        "explanation": "Disabling password expiry on an account is a common persistence step because it keeps stolen or backdoor credentials valid indefinitely.",
        "investigate_next": "Confirm the account's lifecycle requirements, review recent account activity, and restore normal password-expiration policy if the change was unauthorized.",
    },
)
ADMIN_LIKE_NAME_RE = re.compile(r"(^|[^a-z])(admin|administrator)([^a-z]|$)", re.IGNORECASE)
SERVICE_IMAGEPATH_REGISTRY_RE = re.compile(r"\\services\\([^\\]+)\\imagepath$", re.IGNORECASE)
USCHEDULER_VALUE_RE = re.compile(
    r"\\windowsupdate\\orchestrator\\uscheduler\\([^\\]+)\\(cmdline|startarg|pausearg)$",
    re.IGNORECASE,
)
COMPRESS_DEST_RE = re.compile(r"-destinationpath\s+([^\r\n;|]+?\.zip)\b", re.IGNORECASE)
DLL_PATH_RE = re.compile(r"([A-Za-z]:\\[^\"'\r\n]+\.dll)", re.IGNORECASE)
SERVICE_IMAGEPATH_CMD_RE = re.compile(
    r'reg(?:\.exe)?\s+add\s+"?((?:HKLM|HKEY_LOCAL_MACHINE)\\SYSTEM\\CurrentControlSet\\Services\\[^"\\]+)"?.*?\s/v\s+ImagePath\s+/d\s+"?([^"\r\n]+)',
    re.IGNORECASE,
)
SERVICE_REG_PROPERTY_CMD_RE = re.compile(
    r'reg(?:\.exe)?\s+add\s+"?((?:HKLM|HKEY_LOCAL_MACHINE)\\SYSTEM\\CurrentControlSet\\Services\\([^"\\]+))"?.*?\s/v\s+(ImagePath|FailureCommand)\b(?:.*?\s/t\s+\w+\b)?(?:.*?\s/d\s+)(.+)$',
    re.IGNORECASE,
)
SC_SERVICE_PROPERTY_CMD_RE = re.compile(
    r'\bsc(?:\.exe)?\s+(?:(\\\\[^\s]+)\s+)?(config|failure)\s+([^\s"]+)\s+.*?\b(binpath|command)\s*=\s*(.+)$',
    re.IGNORECASE,
)
POWERSHELL_SERVICE_PROPERTY_RE = re.compile(
    r'set-itemproperty\s+-path\s+hklm:(?:\\|\\\\)system(?:\\|\\\\)currentcontrolset(?:\\|\\\\)services(?:\\|\\\\)([^\s"\']+)\s+-name\s+(ImagePath|FailureCommand)\s+-value\s+(.+)$',
    re.IGNORECASE,
)
SC_CREATE_CMD_RE = re.compile(
    r'\bsc(?:\.exe)?\s+(?:(\\\\[^\s]+)\s+)?create\s+([^\s"]+)\s+.*?\bbinpath\s*=\s*(.+)$',
    re.IGNORECASE,
)
USCHEDULER_SHELL_BASENAMES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
}
USCHEDULER_SUSPICIOUS_ARG_MARKERS = (
    "/c ",
    " /c",
    " -enc",
    " -encodedcommand",
    "whoami",
    "powershell",
    "pwsh",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    ">>",
    " >",
    "&",
)
POWERSHELL_CONTEXT_USER_RE = re.compile(r"^\s*User\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def detect(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    privileged_account_alerts, grouped_account_event_ids = _new_privileged_account_provisioning(events)
    tsclient_alerts, grouped_startup_event_ids = _tsclient_startup_folder_drop(events)
    alerts.extend(_com_hijack(events))
    alerts.extend(_powershell_archive_staging(events))
    alerts.extend(_cor_profiler_environment_hijack(events))
    alerts.extend(_sysmon_wmi_permanent_subscription(events))
    alerts.extend(_wmi_activity_subscription(events))
    alerts.extend(_application_shim_persistence(events))
    alerts.extend(_accessibility_features_backdoor(events))
    alerts.extend(_shadow_credentials_modified(events))
    alerts.extend(_adcs_suspicious_certificate_request(events))
    alerts.extend(_adcs_vulnerable_template_change(events))
    alerts.extend(_delegation_configuration_changed(events))
    alerts.extend(_group_policy_object_modified(events))
    alerts.extend(_adminsdholder_permissions_changed(events))
    alerts.extend(_adminsdholder_rights_obfuscation(events))
    alerts.extend(_sql_role_membership_changes(events))
    alerts.extend(_suspicious_spn_assignment(events))
    alerts.extend(_ad_object_owner_changed(events))
    alerts.extend(_adcs_ocsp_configuration_tampering(events))
    alerts.extend(_cross_account_password_change(events))
    alerts.extend(_remote_samr_password_reset(events))
    alerts.extend(_privileged_account_password_reset(events))
    alerts.extend(_account_control_flag_changes(events))
    alerts.extend(_account_rename_manipulation(events))
    alerts.extend(_mass_group_membership_change(events))
    alerts.extend(_self_added_to_group(events))
    alerts.extend(privileged_account_alerts)
    alerts.extend(_process_hidden_account_provisioning(events))
    alerts.extend(_specialaccounts_hidden_user_value(events))
    alerts.extend(_guest_rid_hijack(events))
    alerts.extend(_fake_computer_account_creation(events))
    alerts.extend(_local_sam_account_registry_activity(events))
    alerts.extend(_local_admin_alias_modification(events))
    alerts.extend(_new_smb_share_added(events))
    alerts.extend(_rapid_local_group_membership_churn(events))
    alerts.extend(_transient_scheduled_task(events))
    alerts.extend(_scheduled_task_system_elevation(events))
    alerts.extend(_windows_update_uscheduler_command_hijack(events))
    alerts.extend(_service_failure_command_abuse(events))
    alerts.extend(_service_imagepath_command_abuse(events))
    alerts.extend(_service_creation_command_abuse(events))
    alerts.extend(_service_imagepath_registry_hijack(events))
    alerts.extend(_service_payload_abuse(events))
    alerts.extend(_bits_client_operational_job(events))
    alerts.extend(_bits_notify_sequence(events))
    alerts.extend(_rapid_user_account_lifecycle(events))
    alerts.extend(_guest_account_enabled(events))
    alerts.extend(tsclient_alerts)
    for ev in events:
        alerts.extend(_check(ev, grouped_account_event_ids, grouped_startup_event_ids))
    return alerts


def _extract_clsid(value: str) -> str:
    match = re.search(r"\{[0-9a-fA-F\-]{36}\}", value or "")
    return match.group(0) if match else ""


def _is_user_controlled_location(value: str) -> bool:
    text = (value or "").strip().lower()
    if not text:
        return False
    return any(marker in text for marker in USER_CONTROLLED_PATH_MARKERS)


def _basename(path: str) -> str:
    text = (path or "").replace("\\", "/").strip()
    return os.path.basename(text).lower()


def _extract_process_user(ev: NormalizedEvent) -> str:
    return (
        ev.event_data.get("User", "")
        or ev.domain_user
        or ev.subject_domain_user
        or ev.target_domain_user
        or "unknown"
    )


def _extract_powershell_context_user(context_info: str) -> str:
    match = POWERSHELL_CONTEXT_USER_RE.search(context_info or "")
    return (match.group(1) or "").strip() if match else ""


def _resolve_command_actor(events: List[NormalizedEvent], ev: NormalizedEvent) -> str:
    actor = _extract_process_user(ev)
    if actor and actor.lower() != "unknown":
        return actor
    if ev.event_id != 4104 or not ev.timestamp:
        return actor or "unknown"

    host = ev.computer or "unknown"
    for other in events:
        if other.event_id != 4103 or not other.timestamp:
            continue
        if (other.computer or "unknown") != host:
            continue
        if abs((other.timestamp - ev.timestamp).total_seconds()) > 120:
            continue
        context_user = _extract_powershell_context_user(other.event_data.get("ContextInfo", ""))
        if context_user:
            return context_user
    return actor or "unknown"


def _clean_service_payload(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    text = text.replace('\\"', '"').replace("`\"", '"').strip()
    while len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text.strip().strip('"').strip("'")


def _is_suspicious_service_payload(value: str) -> bool:
    payload = _clean_service_payload(value)
    lowered = payload.lower()
    if not lowered:
        return False
    if any(marker in lowered for marker in SUSPICIOUS_SERVICE_EXECUTION_MARKERS):
        return True
    if re.search(r"\bnc(?:64)?\.exe\b", lowered):
        return True
    if _is_user_controlled_location(lowered):
        return True
    if lowered.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js")) and ("\\" not in lowered and "/" not in lowered):
        return True
    return False


def _bits_remote_host(value: str) -> str:
    text = (value or "").strip()
    if not text.startswith(("http://", "https://")):
        return ""
    try:
        return urlparse(text).netloc.lower()
    except ValueError:
        return ""


def _bits_remote_path(value: str) -> str:
    text = (value or "").strip()
    if not text.startswith(("http://", "https://")):
        return ""
    try:
        parsed = urlparse(text)
    except ValueError:
        return ""
    path = (parsed.path or "").lower()
    if parsed.query:
        return f"{path}?{parsed.query.lower()}"
    return path


def _bits_remote_url_looks_suspicious(value: str) -> bool:
    host = _bits_remote_host(value)
    path = _bits_remote_path(value)
    lowered = (value or "").strip().lower()
    if not host:
        return False
    if host in BENIGN_BITS_REMOTE_HOSTS or any(host.endswith(suffix) for suffix in BENIGN_BITS_REMOTE_HOST_SUFFIXES):
        if any(marker in path for marker in BENIGN_BITS_REMOTE_PATH_MARKERS):
            return False
    return any(marker in lowered for marker in BITS_SUSPICIOUS_REMOTE_MARKERS)


def _bits_job_name_looks_suspicious(value: str) -> bool:
    lowered = (value or "").strip().lower()
    if not lowered:
        return False
    if any(marker in lowered for marker in ("backdoor", "payload", "shell", "stager", "beacon")):
        return True
    if any(
        marker in lowered
        for marker in ("\\cmd.exe", "\\powershell.exe", "\\pwsh.exe", "\\mshta.exe", "\\rundll32.exe", "\\regsvr32.exe")
    ):
        return True
    if _is_user_controlled_location(lowered) and lowered.endswith(
        (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".js", ".msi", ".crx3", ".crxd")
    ):
        return True
    return False


def _is_known_benign_bits_job(job_name: str, remote_url: str, process_paths: List[str]) -> bool:
    name_lower = (job_name or "").strip().lower()
    host = _bits_remote_host(remote_url)
    path = _bits_remote_path(remote_url)
    process_lowers = [(item or "").strip().lower() for item in process_paths if item]

    if name_lower in BENIGN_BITS_JOB_NAMES:
        if host in BENIGN_BITS_REMOTE_HOSTS or any(host.endswith(suffix) for suffix in BENIGN_BITS_REMOTE_HOST_SUFFIXES):
            return True
        if any(marker in path for marker in BENIGN_BITS_REMOTE_PATH_MARKERS):
            return True
        if any(marker in proc for proc in process_lowers for marker in BENIGN_BITS_PROCESS_MARKERS):
            return True

    if any(marker in name_lower for marker in BITS_BENIGN_UPDATER_NAME_MARKERS):
        if host == "clients2.google.com" or host == "storage.googleapis.com" or any(
            host.endswith(suffix) for suffix in BENIGN_BITS_REMOTE_HOST_SUFFIXES
        ):
            return True
        if any("\\google\\update\\googleupdate.exe" in proc for proc in process_lowers):
            return True

    if name_lower == "setupbinary":
        if host == "oneclient.sfx.ms" and "/onedrivesetup.exe" in path:
            if any("\\microsoft\\onedrive\\onedrivestandaloneupdater.exe" in proc for proc in process_lowers):
                return True

    if _is_user_controlled_location(name_lower):
        if host == "clients2.google.com" and "/service/check2" in path:
            if any("\\google\\update\\googleupdate.exe" in proc for proc in process_lowers):
                return True

    return False


def _parse_service_property_command(command: str) -> Tuple[str, str, str, str] | None:
    text = (command or "").strip()
    if not text:
        return None

    match = SERVICE_REG_PROPERTY_CMD_RE.search(text)
    if match:
        service_name = (match.group(2) or "").strip()
        property_name = (match.group(3) or "").strip()
        payload = _clean_service_payload(match.group(4))
        return property_name, service_name, payload, ""

    match = SC_SERVICE_PROPERTY_CMD_RE.search(text)
    if match:
        remote_target = (match.group(1) or "").strip().rstrip("\\")
        service_name = (match.group(3) or "").strip()
        property_name = "FailureCommand" if (match.group(4) or "").lower() == "command" else "ImagePath"
        payload = _clean_service_payload(match.group(5))
        return property_name, service_name, payload, remote_target

    match = POWERSHELL_SERVICE_PROPERTY_RE.search(text)
    if match:
        service_name = (match.group(1) or "").strip().strip("\\/")
        property_name = (match.group(2) or "").strip()
        payload = _clean_service_payload(match.group(3))
        return property_name, service_name, payload, ""

    return None


def _parse_service_create_command(command: str) -> Tuple[str, str, str] | None:
    match = SC_CREATE_CMD_RE.search((command or "").strip())
    if not match:
        return None
    remote_target = (match.group(1) or "").strip().rstrip("\\")
    service_name = (match.group(2) or "").strip()
    payload = _clean_service_payload(match.group(3))
    return remote_target, service_name, payload


def _matches_specific_service_command(command: str) -> bool:
    property_match = _parse_service_property_command(command)
    if property_match and _is_suspicious_service_payload(property_match[2]):
        return True
    create_match = _parse_service_create_command(command)
    if create_match and (_is_suspicious_service_payload(create_match[2]) or create_match[0]):
        return True
    return False


def _extract_sdb_path(text: str) -> str:
    match = re.search(r"([A-Za-z]:\\[^\"\s]+\.sdb)", text or "", re.IGNORECASE)
    return (match.group(1) or "").strip() if match else ""


def _extract_appcompat_target(target: str) -> str:
    text = (target or "").strip()
    lowered = text.lower()
    marker = "\\appcompatflags\\custom\\"
    if marker not in lowered:
        return ""
    remainder = text[lowered.index(marker) + len(marker):]
    return remainder.split("\\", 1)[0].strip()


def _normalize_text(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _extract_first_dll_path(value: str) -> str:
    match = DLL_PATH_RE.search(value or "")
    return (match.group(1) or "").strip() if match else ""


def _is_sysmon_event(ev: NormalizedEvent) -> bool:
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    return "sysmon" in provider or "sysmon" in channel


def _resolve_group_identity(group_name: str, target_sid: str, target_domain: str = "") -> str:
    group = (group_name or "").strip()
    if group and group.lower() not in {"-", "none", "unknown"}:
        return group

    sid = (target_sid or "").strip().lower()
    if sid in WELL_KNOWN_GROUP_SIDS:
        return WELL_KNOWN_GROUP_SIDS[sid]
    if sid.endswith("-512"):
        return "Domain Admins"
    if sid.endswith("-518"):
        return "Schema Admins"
    if sid.endswith("-519"):
        return "Enterprise Admins"

    domain = (target_domain or "").strip()
    return domain if domain and domain.lower() not in {"-", "none"} else "unknown"


def _is_sensitive_group(group: str) -> bool:
    lowered = (group or "").lower()
    return any(name in lowered for name in SENSITIVE_GROUP_NAMES)


def _identity_keys(value: str, sid: str = "") -> Set[str]:
    keys: Set[str] = set()
    text = (value or "").strip()
    if text:
        lowered = text.lower()
        keys.add(lowered)
        if "\\" in lowered:
            keys.add(lowered.split("\\", 1)[1])
    sid_text = (sid or "").strip().lower()
    if sid_text:
        keys.add(sid_text)
    return keys


def _powershell_archive_staging(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue

        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        command_l = command.lower()
        if "compress-archive" not in command_l or "-destinationpath" not in command_l:
            continue

        destination_match = COMPRESS_DEST_RE.search(command)
        destination = (destination_match.group(1) or "").strip().strip("'\"{}()") if destination_match else ""
        if ".zip" not in destination.lower():
            continue
        if "-recurse" not in command_l and "$env:userprofile" not in command_l and "\\users\\" not in command_l:
            continue

        actor = _extract_process_user(ev)
        key = (ev.computer or "unknown", actor, destination.lower())
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1].timestamp <= timedelta(minutes=15):
            existing.append(ev)
        elif existing:
            grouped[(key[0], key[1], f"{key[2]}::{ev.timestamp.isoformat()}")] = [ev]
        else:
            grouped[key] = [ev]

    for (_, actor, destination_key), cluster in grouped.items():
        first_event = cluster[0]
        destination = cluster[0].command_line or cluster[0].event_data.get("ScriptBlockText", "") or destination_key
        destination_match = COMPRESS_DEST_RE.search(destination)
        archive_path = (destination_match.group(1) or "").strip().strip("'\"{}()") if destination_match else destination_key.split("::", 1)[0]
        alerts.append(
            Alert(
                rule_name="PowerShell Archive Staging",
                severity="high",
                mitre_tactic="Collection",
                mitre_technique="T1560.001",
                description=f"{actor} compressed data into {archive_path or 'a ZIP archive'} on {first_event.computer}",
                explanation=(
                    "Compress-Archive packaging of a user's profile or recursively gathered data into a ZIP archive is a common staging step "
                    "before exfiltration, especially when launched from remote PowerShell sessions."
                ),
                confidence="high" if _basename(first_event.parent_process) == "wsmprovhost.exe" else "medium",
                investigate_next=(
                    "Recover the ZIP archive, inspect its contents, and review whether the remote PowerShell session that created it "
                    "was expected administrative activity."
                ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                parent_process=first_event.parent_process,
                evidence={
                    "actor_user": actor,
                    "archive_path": archive_path,
                    "parent_process": first_event.parent_process,
                    "command_lines": [item.command_line[:400] for item in cluster if item.command_line][:5],
                    "archive_event_count": len(cluster),
                    "evidence_strength": "high" if _basename(first_event.parent_process) == "wsmprovhost.exe" else "medium",
                },
            )
        )

    return alerts


def _cor_profiler_environment_hijack(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str], List[NormalizedEvent]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue

        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        command_l = command.lower()
        markers = ("cor_enable_profiling", "cor_profiler", "cor_profiler_path")
        if not all(marker in command_l for marker in markers):
            continue
        if "session manager\\environment" not in command_l and "hklm:\\system\\currentcontrolset\\control\\session manager\\environment" not in command_l:
            continue

        dll_path = _extract_first_dll_path(command)
        if dll_path and not _is_user_controlled_location(dll_path):
            continue

        actor = _extract_process_user(ev)
        key = (ev.computer or "unknown", actor)
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1].timestamp <= timedelta(minutes=20):
            existing.append(ev)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}")] = [ev]
        else:
            grouped[key] = [ev]

    for (host, actor_key), cluster in grouped.items():
        first_event = cluster[0]
        actor = actor_key.split("::", 1)[0]
        command = first_event.command_line or first_event.event_data.get("ScriptBlockText", "") or ""
        dll_path = _extract_first_dll_path(command)
        alerts.append(
            Alert(
                rule_name="COR_PROFILER System Environment Hijack",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1574.012",
                description=f"{actor} configured COR_PROFILER system-wide on {host}",
                explanation=(
                    "Setting COR_ENABLE_PROFILING, COR_PROFILER, and COR_PROFILER_PATH in the system environment forces .NET profiling DLLs "
                    "to load into future processes and is a known execution-flow hijack technique."
                ),
                confidence="high",
                investigate_next=(
                    "Inspect the configured profiler DLL, review which .NET processes load it next, and remove the environment values if they were not expected."
                ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                evidence={
                    "actor_user": actor,
                    "dll_path": dll_path,
                    "environment_scope": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    "command_lines": [item.command_line[:500] for item in cluster if item.command_line][:5],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _service_failure_command_abuse(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str, str], List[Tuple[NormalizedEvent, str]]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue
        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        parsed = _parse_service_property_command(command)
        if not parsed:
            continue
        property_name, service_name, payload, _remote_target = parsed
        if property_name.lower() != "failurecommand":
            continue

        actor = _resolve_command_actor(events, ev)
        key = (ev.computer or "unknown", actor, (service_name or "unknown").lower())
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1][0].timestamp <= timedelta(minutes=20):
            existing.append((ev, payload))
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}", key[2])] = [(ev, payload)]
        else:
            grouped[key] = [(ev, payload)]

    for (host, actor_key, service_key), cluster in grouped.items():
        suspicious_payloads = [(ev, payload) for ev, payload in cluster if _is_suspicious_service_payload(payload)]
        if not suspicious_payloads:
            continue
        primary_event, primary_payload = suspicious_payloads[0]
        actor = actor_key.split("::", 1)[0]
        service_name = service_key or "unknown"
        payloads = [payload for _, payload in suspicious_payloads]
        alerts.append(
            Alert(
                rule_name="Service Failure Command Abuse",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1543.003",
                description=f"{actor} configured {service_name} to launch a failure command on {host}",
                explanation="Changing a service FailureCommand to execute a payload creates a persistence or execution path whenever the service enters a failure state.",
                confidence="high",
                investigate_next="Inspect the service recovery settings, recover the configured failure command, and determine whether the service was intentionally forced to fail afterward.",
                event=primary_event,
                user=actor,
                process=primary_event.process_name,
                service=service_name,
                evidence={
                    "actor_user": actor,
                    "service_name": service_name,
                    "payloads": payloads[:5],
                    "command_lines": [((item.command_line or item.event_data.get('ScriptBlockText', '') or '')[:500]) for item, _ in cluster][:5],
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _service_imagepath_command_abuse(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str, str], List[Dict[str, object]]] = {}
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    process_candidates = [item for item in timed_events if item.event_id in (4688, 1)]

    def _match_payload_process(registry_event: NormalizedEvent, payload: str) -> NormalizedEvent | None:
        if not registry_event.timestamp:
            return None
        host = registry_event.computer or "unknown"
        normalized_payload = _clean_service_payload(payload).lower()
        best_match = None
        best_delta = None

        for other in process_candidates:
            if (other.computer or "unknown") != host or not other.timestamp:
                continue
            command_text = _clean_service_payload(other.command_line or other.event_data.get("CommandLine", "") or "")
            if command_text.lower() != normalized_payload:
                continue
            delta = abs((other.timestamp - registry_event.timestamp).total_seconds())
            if delta > 120:
                continue
            if best_delta is None or delta < best_delta:
                best_match = other
                best_delta = delta

        return best_match

    for ev in timed_events:
        actor = "unknown"
        service_name = ""
        payload = ""
        command_text = ""
        registry_path = ""
        process_name = ev.process_name

        if ev.event_id in (4688, 1, 4104):
            command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
            parsed = _parse_service_property_command(command)
            if not parsed:
                continue
            property_name, service_name, payload, _remote_target = parsed
            if property_name.lower() != "imagepath":
                continue
            actor = _resolve_command_actor(events, ev)
            command_text = command
        elif ev.event_id == 13 and _is_sysmon_registry_event(ev):
            if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
                continue
            registry_path = _registry_target(ev)
            match = SERVICE_IMAGEPATH_REGISTRY_RE.search(registry_path)
            if not match:
                continue
            service_name = (match.group(1) or "").strip()
            payload = _clean_service_payload(ev.event_data.get("Details", "") or ev.event_data.get("NewValue", "") or "")
            if not payload:
                continue
            matched_process = _match_payload_process(ev, payload)
            actor = _resolve_command_actor(events, matched_process) if matched_process else _resolve_command_actor(events, ev)
            if matched_process:
                command_text = matched_process.command_line or matched_process.event_data.get("CommandLine", "") or ""
                process_name = matched_process.process_name or process_name
        else:
            continue

        key = (ev.computer or "unknown", actor, (service_name or "unknown").lower())
        entry = {
            "event": ev,
            "payload": payload,
            "command_text": command_text,
            "registry_path": registry_path,
            "process_name": process_name,
        }
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1]["event"].timestamp <= timedelta(minutes=20):
            existing.append(entry)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}", key[2])] = [entry]
        else:
            grouped[key] = [entry]

    for (host, actor_key, service_key), cluster in grouped.items():
        suspicious_entries = [item for item in cluster if _is_suspicious_service_payload(str(item["payload"]))]
        if not suspicious_entries:
            continue
        primary_entry = suspicious_entries[0]
        primary_event = primary_entry["event"]
        actor = actor_key.split("::", 1)[0]
        service_name = service_key or "unknown"
        payloads = []
        command_lines = []
        registry_paths = []
        process_paths = []

        for item in suspicious_entries:
            payload_value = str(item["payload"])
            if payload_value and payload_value not in payloads:
                payloads.append(payload_value)

            command_value = str(item["command_text"] or "")
            if not command_value:
                event = item["event"]
                command_value = event.command_line or event.event_data.get("ScriptBlockText", "") or ""
            if command_value:
                command_value = command_value[:500]
                if command_value not in command_lines:
                    command_lines.append(command_value)

            registry_value = str(item["registry_path"] or "")
            if registry_value and registry_value not in registry_paths:
                registry_paths.append(registry_value)

            process_value = str(item["process_name"] or "")
            if process_value and process_value not in process_paths:
                process_paths.append(process_value)

        alerts.append(
            Alert(
                rule_name="Service ImagePath Command Abuse",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1543.003",
                description=f"{actor} changed {service_name} ImagePath to a suspicious payload on {host}",
                explanation="Changing a service ImagePath to an attacker-controlled command hijacks future service execution and is a common service-based persistence technique.",
                confidence="high",
                investigate_next="Recover the modified ImagePath, confirm whether the service was started afterward, and inspect the payload path or interpreter for follow-on execution.",
                event=primary_event,
                user=actor,
                process=primary_entry["process_name"] or primary_event.process_name,
                service=service_name,
                evidence={
                    "actor_user": actor,
                    "service_name": service_name,
                    "payloads": payloads[:5],
                    "command_lines": command_lines[:5],
                    "registry_paths": registry_paths[:5],
                    "process_paths": process_paths[:5],
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _service_creation_command_abuse(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str, str, str], List[Tuple[NormalizedEvent, str]]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue
        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        parsed = _parse_service_create_command(command)
        if not parsed:
            continue
        remote_target, service_name, payload = parsed
        if not remote_target and not _is_suspicious_service_payload(payload):
            continue

        actor = _resolve_command_actor(events, ev)
        key = (ev.computer or "unknown", actor, (service_name or "unknown").lower(), remote_target.lower())
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1][0].timestamp <= timedelta(minutes=20):
            existing.append((ev, payload))
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}", key[2], key[3])] = [(ev, payload)]
        else:
            grouped[key] = [(ev, payload)]

    for (host, actor_key, service_key, remote_target), cluster in grouped.items():
        primary_event, primary_payload = cluster[0]
        actor = actor_key.split("::", 1)[0]
        service_name = service_key or "unknown"
        is_remote = bool(remote_target)
        alerts.append(
            Alert(
                rule_name="Remote Service Creation Command" if is_remote else "Service Creation Command",
                severity="high",
                mitre_tactic="Lateral Movement" if is_remote else "Persistence",
                mitre_technique="T1021.002" if is_remote else "T1543.003",
                description=(
                    f"{actor} issued a remote service creation command against {remote_target or host}"
                    if is_remote
                    else f"{actor} created service {service_name} with a suspicious payload on {host}"
                ),
                explanation=(
                    "Creating a remote service with sc.exe is a common way to execute payloads laterally over the Service Control Manager."
                    if is_remote
                    else "Creating a service with a bare or suspicious payload path is a common way to establish service-based persistence."
                ),
                confidence="high",
                investigate_next=(
                    "Confirm whether the remote service was created successfully, inspect the target host for follow-on service execution, and recover the payload path."
                    if is_remote
                    else "Review the created service definition, validate the payload path, and determine whether the service was started after creation."
                ),
                event=primary_event,
                user=actor,
                process=primary_event.process_name,
                service=service_name,
                evidence={
                    "actor_user": actor,
                    "service_name": service_name,
                    "remote_target": remote_target,
                    "payloads": [payload for _, payload in cluster[:5]],
                    "command_lines": [((item.command_line or item.event_data.get('ScriptBlockText', '') or '')[:500]) for item, _ in cluster][:5],
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _service_imagepath_registry_hijack(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str], List[Tuple[NormalizedEvent, str, str]]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4688, 1, 4104):
            continue

        command = ev.command_line or ev.event_data.get("ScriptBlockText", "") or ""
        match = SERVICE_IMAGEPATH_CMD_RE.search(command)
        if not match:
            continue

        service_key = (match.group(1) or "").strip()
        image_path = (match.group(2) or "").strip().strip("'\"")
        image_path_l = image_path.lower()
        suspicious = any(marker in image_path_l for marker in SUSPICIOUS_SERVICE_EXECUTION_MARKERS)
        if not suspicious:
            continue

        key = (ev.computer or "unknown", service_key.lower())
        payload = (ev, service_key, image_path)
        existing = grouped.get(key)
        if existing and ev.timestamp - existing[-1][0].timestamp <= timedelta(minutes=10):
            existing.append(payload)
        elif existing:
            grouped[(key[0], f"{key[1]}::{ev.timestamp.isoformat()}")] = [payload]
        else:
            grouped[key] = [payload]

    for (_, service_key_key), cluster in grouped.items():
        first_event, service_key, image_path = cluster[0]
        actor = _extract_process_user(first_event)
        service_name = service_key.rstrip("\\").split("\\")[-1]
        alerts.append(
            Alert(
                rule_name="Service ImagePath Registry Hijack",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1574.011",
                description=f"{actor} changed {service_name} ImagePath to {image_path} on {first_event.computer}",
                explanation=(
                    "Direct registry modification of a service ImagePath to an interpreter or attacker-controlled command hijacks future service execution "
                    "without using standard service-management tooling."
                ),
                confidence="high",
                investigate_next=(
                    "Restore the service ImagePath, determine whether the service was started after the change, and inspect the configured command or payload path."
                ),
                event=first_event,
                user=actor,
                process=first_event.process_name,
                service=service_name,
                evidence={
                    "actor_user": actor,
                    "service_key": service_key,
                    "service_name": service_name,
                    "image_path": image_path,
                    "command_lines": [item[0].command_line[:400] for item in cluster if item[0].command_line][:5],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _windows_update_uscheduler_command_hijack(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    grouped: Dict[Tuple[str, str], List[Tuple[NormalizedEvent, str, str, str]]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if not _is_sysmon_registry_event(ev) or ev.event_id != 13:
            continue
        if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
            continue

        target = _registry_target(ev)
        match = USCHEDULER_VALUE_RE.search(target)
        if not match:
            continue

        scheduler_id = (match.group(1) or "").strip()
        value_name = (match.group(2) or "").strip().lower()
        details = _clean_service_payload(ev.event_data.get("Details", "") or ev.event_data.get("NewValue", "") or "")
        key = (ev.computer or "unknown", scheduler_id)
        grouped.setdefault(key, []).append((ev, value_name, details, target))

    for (host, scheduler_id), cluster in grouped.items():
        values = {value_name: details for _, value_name, details, _ in cluster if details}
        cmd_line = values.get("cmdline", "")
        if not cmd_line:
            continue

        cmd_line_l = cmd_line.lower()
        cmd_base = _basename(cmd_line_l)
        arg_values = [values.get("startarg", ""), values.get("pausearg", "")]
        combined_args = " ".join(item for item in arg_values if item).lower()
        suspicious_args = any(marker in combined_args for marker in USCHEDULER_SUSPICIOUS_ARG_MARKERS)
        suspicious_cmd = (
            (cmd_base in USCHEDULER_SHELL_BASENAMES and suspicious_args)
            or any(marker in cmd_line_l for marker in ("powershell", "pwsh", "rundll32", "regsvr32", "mshta"))
            or (_is_user_controlled_location(cmd_line_l) and cmd_line_l.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta")))
        )
        if not suspicious_cmd:
            continue

        first_event = cluster[0][0]
        registry_paths = [target for _, _, _, target in cluster if target][:5]
        alerts.append(
            Alert(
                rule_name="Windows Update UScheduler Command Hijack",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1574",
                description=f"Windows Update Orchestrator UScheduler {scheduler_id} was hijacked to run {cmd_line} on {host}",
                explanation=(
                    "Tampering with the Windows Update Orchestrator UScheduler cmdLine and argument values is associated with "
                    "CVE-2020-1313-style privilege escalation, where trusted update orchestration runs attacker-controlled commands."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the modified UScheduler values, determine whether the orchestrator task executed, and inspect the payload or "
                    "arguments for follow-on privilege escalation."
                ),
                event=first_event,
                user=_extract_process_user(first_event),
                process=first_event.process_name,
                evidence={
                    "scheduler_id": scheduler_id,
                    "cmd_line": cmd_line,
                    "start_arg": values.get("startarg", ""),
                    "pause_arg": values.get("pausearg", ""),
                    "registry_paths": registry_paths,
                    "event_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _wmi_subscription_fingerprint(detail_text: str, query_text: str) -> str:
    detail = detail_text or ""
    query = query_text or ""
    names = sorted(
        {
            _normalize_text(match)
            for match in WMI_NAME_RE.findall(detail)
            if _normalize_text(match)
        }
    )
    consumer_types = sorted(
        {
            _normalize_text(match)
            for match in WMI_CONSUMER_RE.findall(detail)
            if _normalize_text(match)
        }
    )
    commands = sorted(
        {
            _normalize_text(match)
            for match in WMI_COMMAND_RE.findall(detail)
            if _normalize_text(match)
        }
    )
    normalized_query = _normalize_text(query)
    if normalized_query:
        normalized_query = re.sub(r"\b\d{3,}\b", "", normalized_query).strip()
    detail_fallback = _normalize_text(detail)
    if detail_fallback:
        detail_fallback = re.sub(r"\b\d{3,}\b", "", detail_fallback).strip()

    parts = names[:3] + consumer_types[:2] + commands[:1]
    if normalized_query:
        parts.append(normalized_query[:220])
    if not parts and detail_fallback:
        parts.append(detail_fallback[:220])
    return " | ".join(parts) or "generic-wmi-subscription"


def _tsclient_startup_folder_drop(events: List[NormalizedEvent]) -> Tuple[List[Alert], Set[int]]:
    alerts: List[Alert] = []
    suppressed_ids: Set[int] = set()
    seen = set()

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id != 11 or not _is_sysmon_event(ev):
            continue

        target = (ev.event_data.get("TargetFilename", "") or "").strip()
        target_l = target.lower()
        if "startup" not in target_l:
            continue
        if _basename(ev.process_name) != "mstsc.exe":
            continue

        match = STARTUP_TARGET_RE.search(target_l)
        startup_user = match.group(1) if match else ""
        key = ((ev.computer or "unknown").lower(), target_l)
        if key in seen:
            continue
        seen.add(key)
        suppressed_ids.add(id(ev))

        alerts.append(
            Alert(
                rule_name="TSCLIENT Startup Folder Drop",
                severity="critical",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.001",
                description=f"mstsc.exe dropped a startup payload for {startup_user or 'a remote user'} on {ev.computer}",
                explanation=(
                    "Writing directly into another user's Startup folder from mstsc.exe is consistent with RDP drive-redirection abuse used to establish persistence or stage remote execution."
                ),
                confidence="high",
                investigate_next=(
                    "Recover the dropped startup payload, determine whether RDP drive redirection was used, and inspect the remote logon session that created the file."
                ),
                event=ev,
                process=ev.process_name,
                user=startup_user,
                evidence={
                    "process_name": ev.process_name,
                    "target_file": target,
                    "startup_user": startup_user,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts, suppressed_ids


def _wmi_activity_subscription(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], List[Tuple[NormalizedEvent, str, str]]] = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (5859, 5860, 5861):
            continue
        provider_context = f"{ev.provider} {ev.channel}".lower()
        if "wmi-activity" not in provider_context:
            continue

        detail_text = "\n".join(str(value) for value in ev.event_data.values() if value)
        detail_lower = detail_text.lower()
        if not any(marker in detail_lower for marker in WMI_ACTIVITY_SUBSCRIPTION_MARKERS):
            continue

        host = ev.computer or "unknown"
        query_text = (ev.event_data.get("Query", "") or ev.event_data.get("Operation", "") or "").strip()
        fingerprint = _wmi_subscription_fingerprint(detail_text, query_text)
        grouped.setdefault((host, fingerprint), []).append((ev, detail_text, query_text))

    merged_groups: List[Tuple[str, List[Tuple[NormalizedEvent, str, str]], str]] = []
    grouped_by_host: Dict[str, List[Tuple[str, List[Tuple[NormalizedEvent, str, str]]]]] = {}
    for (host, fingerprint), cluster in grouped.items():
        grouped_by_host.setdefault(host, []).append((fingerprint, cluster))

    for host, entries in grouped_by_host.items():
        entries = sorted(entries, key=lambda item: min(ev.timestamp for ev, _, _ in item[1]))
        host_groups: List[Dict[str, object]] = []
        for fingerprint, cluster in entries:
            cluster_start = min(ev.timestamp for ev, _, _ in cluster)
            cluster_has_binding = any(ev.event_id == 5861 for ev, _, _ in cluster)
            is_query_only = "__instanceoperationevent" in fingerprint or "__filtertoconsumerbinding" in fingerprint
            merged = False
            for existing in host_groups:
                existing_start = existing["first_seen"]
                existing_has_binding = existing["has_binding"]
                existing_is_query_only = existing["is_query_only"]
                if abs((cluster_start - existing_start).total_seconds()) > 900:
                    continue
                if (cluster_has_binding and existing_is_query_only) or (existing_has_binding and is_query_only):
                    existing["cluster"].extend(cluster)
                    existing["first_seen"] = min(existing_start, cluster_start)
                    existing["has_binding"] = existing_has_binding or cluster_has_binding
                    merged = True
                    break
            if not merged:
                host_groups.append(
                    {
                        "fingerprint": fingerprint,
                        "cluster": list(cluster),
                        "first_seen": cluster_start,
                        "has_binding": cluster_has_binding,
                        "is_query_only": is_query_only,
                    }
                )

        for item in host_groups:
            merged_groups.append((host, item["cluster"], item["fingerprint"]))

    for host, cluster, fingerprint in merged_groups:
        first_event = min(cluster, key=lambda item: item[0].timestamp)
        first = first_event[0]
        has_binding = any(ev.event_id == 5861 for ev, _, _ in cluster)
        details = []
        queries = []
        consumers = []
        for ev, detail_text, query_text in cluster:
            snippet = " ".join(line.strip() for line in detail_text.splitlines() if line.strip())
            if snippet and snippet not in details:
                details.append(snippet[:500])
            if query_text and query_text not in queries:
                queries.append(query_text[:400])
            consumer_hits = [match for match in WMI_CONSUMER_RE.findall(detail_text) if match]
            for hit in consumer_hits:
                normalized = _normalize_text(hit)
                if normalized and normalized not in consumers:
                    consumers.append(normalized)

        actor_values = sorted(
            {
                (ev.event_data.get("User", "") or _extract_process_user(ev)).strip()
                for ev, _, _ in cluster
                if (ev.event_data.get("User", "") or _extract_process_user(ev)).strip()
            }
        )
        actor = actor_values[0] if len(actor_values) == 1 else actor_values[0] if actor_values else "unknown"
        alerts.append(
            Alert(
                rule_name="WMI Event Subscription Persistence",
                severity="critical" if has_binding else "high",
                mitre_tactic="Persistence",
                mitre_technique="T1546.003",
                description=f"WMI Activity subscription events created a consumer/binding chain on {host}",
                explanation=(
                    "WMI-Activity Operational events showing __EventFilter, consumer, or FilterToConsumerBinding details indicate "
                    "WMI event subscription persistence even when classic Operational event IDs 19/20/21 are absent. Repeated events "
                    "for the same subscription content are collapsed into one finding."
                ),
                confidence="high" if has_binding else "medium",
                investigate_next=(
                    "Review the WMI filter query, consumer type, and binding details, then determine whether the subscription executes "
                    "commands or survives reboots as persistence."
                ),
                event=first,
                user=actor,
                evidence={
                    "actor_user": actor if len(actor_values) <= 1 else actor_values,
                    "event_ids": [ev.event_id for ev, _, _ in cluster],
                    "queries": queries[:10],
                    "subscription_details": details[:10],
                    "binding_present": has_binding,
                    "consumer_details": consumers[:10],
                    "subscription_fingerprint": fingerprint,
                    "collapsed_event_count": len(cluster),
                    "timestamps": [ev.timestamp.isoformat() if ev.timestamp else None for ev, _, _ in cluster],
                    "evidence_strength": "high" if has_binding else "medium",
                },
            )
        )

    return alerts


def _application_shim_persistence(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        provider_context = f"{ev.provider} {ev.channel}".lower()
        if "sysmon" not in provider_context:
            continue

        registry_target = _registry_target(ev)
        registry_lower = registry_target.lower()
        target_filename = (ev.event_data.get("TargetFilename", "") or "").strip()
        target_filename_lower = target_filename.lower()
        process_name = ev.process_name or ev.event_data.get("Image", "")
        process_base = _basename(process_name)
        cmd = ev.command_line or ev.event_data.get("CommandLine", "") or ""
        cmd_lower = cmd.lower()

        interesting = False
        target_binary = ""
        sdb_path = ""
        if ev.event_id == 1 and process_base == "sdbinst.exe" and ".sdb" in cmd_lower:
            interesting = True
            sdb_path = _extract_sdb_path(cmd)
        elif ev.event_id == 11 and "\\windows\\apppatch\\custom\\" in target_filename_lower and target_filename_lower.endswith(".sdb"):
            interesting = True
            sdb_path = target_filename
        elif ev.event_id == 13 and (
            "\\appcompatflags\\custom\\" in registry_lower or "\\appcompatflags\\installedsdb\\" in registry_lower
        ):
            interesting = True
            sdb_path = _extract_sdb_path(ev.event_data.get("Details", "") or registry_target)
            target_binary = _extract_appcompat_target(registry_target)

        if not interesting:
            continue

        key = (ev.computer or "unknown")
        clusters = grouped.setdefault(key, [])
        if clusters and ev.timestamp - clusters[-1][-1].timestamp <= timedelta(hours=2):
            clusters[-1].append(ev)
        else:
            clusters.append([ev])

    for host, clusters in grouped.items():
        for cluster in clusters:
            first_event = cluster[0]
            registry_paths = sorted(
                {
                    _registry_target(ev)
                    for ev in cluster
                    if _registry_target(ev)
                }
            )
            sdb_paths = sorted(
                {
                    _extract_sdb_path(ev.command_line or ev.event_data.get("Details", "") or ev.event_data.get("TargetFilename", "") or "")
                    or (ev.event_data.get("TargetFilename", "") or "")
                    for ev in cluster
                    if (
                        _extract_sdb_path(ev.command_line or ev.event_data.get("Details", "") or ev.event_data.get("TargetFilename", "") or "")
                        or (ev.event_data.get("TargetFilename", "") or "")
                    )
                }
            )
            target_binaries = sorted(
                {
                    _extract_appcompat_target(_registry_target(ev)) or _basename(ev.process_name)
                    for ev in cluster
                    if (_extract_appcompat_target(_registry_target(ev)) or _basename(ev.process_name))
                }
            )
            is_accessibility_target = any(item in ACCESSIBILITY_BINARIES for item in target_binaries)
            alerts.append(
                Alert(
                    rule_name="Application Shim Persistence",
                    severity="critical" if is_accessibility_target else "high",
                    mitre_tactic="Persistence",
                    mitre_technique="T1546.011",
                    description=f"Application compatibility shim data was installed on {host}",
                    explanation=(
                        "sdbinst.exe activity plus AppCompatFlags registry entries or AppPatch Custom .sdb files indicate an application "
                        "shim was installed, which attackers abuse to redirect execution or backdoor target binaries."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Recover the .sdb file, inspect which binaries it targets, and verify whether the compatibility database was legitimately installed."
                    ),
                    event=first_event,
                    process=first_event.process_name,
                    registry_key=registry_paths[0] if registry_paths else "",
                    evidence={
                        "registry_paths": registry_paths[:20],
                        "sdb_paths": sdb_paths[:20],
                        "target_binaries": target_binaries[:10],
                        "processes": sorted({_basename(ev.process_name) for ev in cluster if ev.process_name}),
                        "event_count": len(cluster),
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _accessibility_features_backdoor(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    grouped: Dict[Tuple[str, str, str], List[Tuple[NormalizedEvent, List[NormalizedEvent], bool, bool]]] = {}

    for ev in timed_events:
        if ev.event_id not in (4688, 1):
            continue

        proc = _basename(ev.process_name)
        parent = _basename(ev.parent_process)
        if parent not in ACCESSIBILITY_TRIGGER_PARENTS or proc not in ACCESSIBILITY_BINARIES:
            continue

        process_path = (ev.process_name or ev.event_data.get("Image", "") or "").strip()
        description = (ev.event_data.get("Description", "") or "").strip().lower()
        suspicious_path = bool(process_path) and not process_path.lower().startswith("c:\\windows\\system32\\")
        description_mismatch = any(marker in description for marker in ("command processor", "powershell", "console host"))

        follow_on = []
        window_end = ev.timestamp + timedelta(minutes=5)
        for other in timed_events:
            if other.timestamp <= ev.timestamp or other.timestamp > window_end:
                continue
            if (other.computer or "") != (ev.computer or ""):
                continue
            if _basename(other.parent_process) != proc:
                continue
            if _basename(other.process_name) in ACCESSIBILITY_FOLLOW_ON:
                follow_on.append(other)

        if not suspicious_path and not description_mismatch and not follow_on:
            continue

        actor = _extract_process_user(ev)
        key = (
            ev.computer or "unknown",
            (process_path or proc).lower() or proc,
            actor.lower() or "unknown",
        )
        grouped.setdefault(key, []).append((ev, follow_on, suspicious_path, description_mismatch))

    for (_, _, _), cluster in grouped.items():
        first_event = min(cluster, key=lambda item: item[0].timestamp)[0]
        proc = _basename(first_event.process_name)
        process_path = (first_event.process_name or first_event.event_data.get("Image", "") or "").strip()
        actor_values = sorted(
            {
                (_extract_process_user(ev) or "unknown").strip() or "unknown"
                for ev, _, _, _ in cluster
            }
        )
        actor = actor_values[0] if len(actor_values) == 1 else actor_values[0] if actor_values else "unknown"
        follow_on_processes = []
        follow_on_commands = []
        timestamps = []
        suspicious_path = False
        description_mismatch = False
        for ev, follow_on, suspicious_path_hit, mismatch_hit in cluster:
            timestamps.append(ev.timestamp.isoformat() if ev.timestamp else None)
            suspicious_path = suspicious_path or suspicious_path_hit
            description_mismatch = description_mismatch or mismatch_hit
            for item in follow_on:
                if item.process_name and item.process_name not in follow_on_processes:
                    follow_on_processes.append(item.process_name)
                if item.command_line and item.command_line[:300] not in follow_on_commands:
                    follow_on_commands.append(item.command_line[:300])

        observation_note = f" [{len(cluster)} observations]" if len(cluster) > 1 else ""
        alerts.append(
            Alert(
                rule_name="Accessibility Features Backdoor",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1546.008",
                description=f"Accessibility binary {process_path or proc} launched from {first_event.parent_process or _basename(first_event.parent_process)} on {first_event.computer}{observation_note}",
                explanation=(
                    "Abusing accessibility binaries such as Utilman or osk can provide a SYSTEM-level backdoor at the logon screen. "
                    "This alert fires when the launched image path is non-standard, its description mismatches the binary, or it immediately spawns shell-like activity. "
                    "Repeated launches of the same backdoored image are collapsed into one finding."
                ),
                confidence="high",
                investigate_next=(
                    "Verify the on-disk binary for the accessibility executable, inspect the parent logon process chain, and review any shell or discovery commands it spawned."
                ),
                event=first_event,
                user=actor,
                process=process_path,
                parent_process=first_event.parent_process,
                evidence={
                    "actor_user": actor if len(actor_values) <= 1 else actor_values,
                    "accessibility_binary": proc,
                    "launched_image": process_path,
                    "parent_process": first_event.parent_process,
                    "description": first_event.event_data.get("Description", ""),
                    "suspicious_path": suspicious_path,
                    "description_mismatch": description_mismatch,
                    "follow_on_processes": follow_on_processes,
                    "follow_on_commands": follow_on_commands,
                    "collapsed_event_count": len(cluster),
                    "timestamps": timestamps,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _com_hijack(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    suspicious_inproc = {}
    treat_as = []

    for ev in events:
        if ev.event_id != 13:
            continue
        provider_context = f"{ev.provider} {ev.channel}".lower()
        if "sysmon" not in provider_context:
            continue

        target = (ev.event_data.get("TargetObject", "") or ev.event_data.get("ObjectName", "") or "").strip()
        target_lower = target.lower()
        if "\\clsid\\" not in target_lower:
            continue

        details = (ev.event_data.get("Details", "") or ev.event_data.get("NewValue", "") or "").strip()
        clsid = _extract_clsid(target)
        if not clsid:
            continue

        if "\\inprocserver32" in target_lower and _is_user_controlled_location(details):
            suspicious_inproc[(ev.computer or "", clsid)] = {
                "event": ev,
                "target": target,
                "details": details,
            }
        elif "\\treatas" in target_lower:
            treat_as.append((ev, target, details, clsid))

    emitted = set()

    for (host, clsid), info in suspicious_inproc.items():
        ev = info["event"]
        target = info["target"]
        dll_path = info["details"]
        related_treatas = []
        for treat_ev, treat_target, treat_value, treat_clsid in treat_as:
            if (treat_ev.computer or "") != host:
                continue
            if treat_value.strip().upper() != clsid.upper():
                continue
            related_treatas.append(
                {
                    "registry_key": treat_target,
                    "target_clsid": treat_clsid,
                    "details": treat_value,
                    "timestamp": treat_ev.timestamp.isoformat() if treat_ev.timestamp else None,
                }
            )

        emitted.add((host, clsid))
        alerts.append(
            Alert(
                rule_name="COM Hijacking Persistence",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1546.015",
                description=(
                    "A COM object registry key was modified to redirect execution to a custom DLL. "
                    "This technique is commonly used for persistence."
                ),
                explanation=(
                    f"CLSID {clsid} on {host or 'unknown host'} now points to {dll_path}. "
                    "Attackers hijack InProcServer32 or TreatAs keys so trusted software loads a malicious DLL."
                ),
                confidence="high",
                investigate_next=(
                    f"Inspect DLL path {dll_path}, compare the CLSID {clsid} to a known-good baseline, "
                    "and determine which COM client would load the modified object."
                ),
                event=ev,
                registry_key=target,
                evidence={
                    "clsid": clsid,
                    "registry_key": target,
                    "dll_path": dll_path,
                    "related_treatas": related_treatas,
                    "process_image": ev.event_data.get("Image", ""),
                    "evidence_strength": "high",
                },
            )
        )

    for treat_ev, treat_target, treat_value, treat_clsid in treat_as:
        key = (treat_ev.computer or "", treat_value.strip())
        if not treat_value or key in emitted:
            continue
        if key not in suspicious_inproc:
            continue

        info = suspicious_inproc[key]
        alerts.append(
            Alert(
                rule_name="COM Hijacking Persistence",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1546.015",
                description=(
                    "A COM object registry key was modified to redirect execution to a custom DLL. "
                    "This technique is commonly used for persistence."
                ),
                explanation=(
                    f"TreatAs on {treat_ev.computer or 'unknown host'} maps CLSID {treat_clsid} to {treat_value}, "
                    f"which resolves to user-controlled DLL {info['details']}."
                ),
                confidence="high",
                investigate_next=(
                    f"Inspect DLL path {info['details']}, review the TreatAs chain for CLSID {treat_clsid}, "
                    "and identify the application that would invoke the hijacked COM object."
                ),
                event=treat_ev,
                registry_key=treat_target,
                evidence={
                    "clsid": treat_clsid,
                    "treatas_target": treat_value,
                    "linked_dll_path": info["details"],
                    "linked_inproc_key": info["target"],
                    "process_image": treat_ev.event_data.get("Image", ""),
                    "evidence_strength": "high",
                },
            )
        )
        emitted.add(key)

    return alerts


def _transient_scheduled_task(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    created = [
        ev for ev in events
        if ev.event_id == 4698 and ev.timestamp
    ]
    deleted = [
        ev for ev in events
        if ev.event_id == 4699 and ev.timestamp
    ]

    for create in created:
        task_name = create.event_data.get("TaskName", "") or create.task_name
        if not task_name:
            continue

        subject_logon_id = create.event_data.get("SubjectLogonId", "")
        task_content = create.event_data.get("TaskContent", "") or ""
        for remove in deleted:
            if (remove.computer or "") != (create.computer or ""):
                continue
            if (remove.event_data.get("TaskName", "") or remove.task_name) != task_name:
                continue
            if remove.timestamp < create.timestamp or remove.timestamp - create.timestamp > timedelta(minutes=5):
                continue
            if subject_logon_id and remove.event_data.get("SubjectLogonId", "") not in {"", subject_logon_id}:
                continue

            content_l = task_content.lower()
            suspicious = any(marker in content_l for marker in ("cmd.exe", "powershell", "rundll32", "mshta", "regsvr32", "%windir%\\temp"))
            alerts.append(
                Alert(
                    rule_name="Transient Scheduled Task Execution",
                    severity="critical" if suspicious else "high",
                    mitre_tactic="Execution",
                    mitre_technique="T1053.005",
                    description=f"Task '{task_name}' was created and deleted rapidly on {create.computer}",
                    explanation="Short-lived scheduled tasks are commonly used by ATexec/SMBexec-style tooling to launch commands and immediately remove evidence.",
                    confidence="high",
                    investigate_next="Review the task XML, recover the executed command, and correlate with nearby remote logons, share access, or service-control activity.",
                    event=create,
                    scheduled_task=task_name,
                    evidence={
                        "task_name": task_name,
                        "task_content": task_content[:800],
                        "created_at": create.timestamp.isoformat() if create.timestamp else None,
                        "deleted_at": remove.timestamp.isoformat() if remove.timestamp else None,
                        "subject_logon_id": subject_logon_id,
                        "evidence_strength": "high",
                    },
                )
            )
            break

    return alerts


def _service_payload_abuse(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id not in (7045, 4697):
            continue
        binary = (
            ev.event_data.get("ImagePath", "")
            or ev.event_data.get("ServiceFileName", "")
            or ""
        )
        binary_l = binary.lower()
        service_name = ev.event_data.get("ServiceName", "") or ev.service_name

        if "cmd.exe /c echo" in binary_l and "\\\\.\\pipe\\" in binary_l:
            dedupe_key = ("psexec", ev.computer or "", (service_name or "").lower(), binary_l)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            alerts.append(
                Alert(
                    rule_name="PsExec Service Payload",
                    severity="critical",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021.002",
                    description=f"Service '{service_name or 'unknown'}' on {ev.computer} stages a named-pipe payload",
                    explanation="PsExec-style payloads often use temporary services that write to a local named pipe before command execution.",
                    confidence="high",
                    investigate_next="Correlate this service with remote logon, SMB access, and the named pipe involved to confirm remote execution source and payload.",
                    event=ev,
                    service=service_name,
                    evidence={
                        "service_name": service_name,
                        "binary": binary,
                        "pipe_payload": True,
                        "evidence_strength": "high",
                    },
                )
            )

        if "%comspec%" in binary_l and "%temp%\\execute.bat" in binary_l and "__output" in binary_l:
            dedupe_key = ("smbexec", ev.computer or "", (service_name or "").lower(), binary_l)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            alerts.append(
                Alert(
                    rule_name="SMBexec Service Payload",
                    severity="critical",
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021.002",
                    description=f"Service '{service_name or 'unknown'}' on {ev.computer} matches an SMBexec-style payload",
                    explanation="SMBexec commonly registers a service that builds a temporary batch file, runs it through COMSPEC, and writes output back to an admin share.",
                    confidence="high",
                    investigate_next="Recover the service command, inspect the admin-share output path, and correlate with remote share access or named-pipe activity.",
                    event=ev,
                    service=service_name,
                    evidence={
                        "service_name": service_name,
                        "binary": binary,
                        "smbexec_style": True,
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _bits_notify_sequence(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    suspicious_children = {"cmd.exe", "powershell.exe", "pwsh.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"}
    parents = [
        ev for ev in events
        if ev.event_id in (4688, 1)
        and (ev.process_name or ev.event_data.get("Image", "")).replace("\\", "/").split("/")[-1].lower() == "mobsync.exe"
        and "-embedding" in (ev.command_line or "").lower()
        and ev.timestamp
    ]
    children = [
        ev for ev in events
        if ev.event_id in (4688, 1)
        and (ev.process_name or ev.event_data.get("Image", "")).replace("\\", "/").split("/")[-1].lower() in suspicious_children
        and ev.timestamp
    ]

    seen = set()
    for parent in parents:
        host = parent.computer or "unknown"
        for child in children:
            if (child.computer or "") != host:
                continue
            if child.timestamp < parent.timestamp or child.timestamp - parent.timestamp > timedelta(minutes=2):
                continue
            child_name = (child.process_name or child.event_data.get("Image", "")).replace("\\", "/").split("/")[-1].lower()
            dedupe_key = (host, child_name, (child.command_line or "").lower())
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            alerts.append(Alert(
                rule_name="BITS Notify Command Execution", severity="critical",
                mitre_tactic="Persistence", mitre_technique="T1197",
                description=f"BITS notify callback activity launched {child_name} on {host}",
                explanation="mobsync.exe embedding followed closely by a suspicious child process is consistent with a BITS job notify callback executing attacker-controlled content.",
                confidence="high",
                investigate_next="Inspect the BITS job configuration, recover the notify command, and determine whether the callback installed persistence or launched additional payloads.",
                event=child,
                process=child.process_name,
                evidence={
                    "parent_process": parent.process_name or parent.event_data.get("Image", ""),
                    "parent_command_line": (parent.command_line or "")[:400],
                    "child_process": child.process_name,
                    "child_command_line": (child.command_line or "")[:400],
                    "evidence_strength": "high",
                },
            ))

    return alerts


def _bits_client_operational_job(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = {}

    for ev in events:
        provider_context = f"{ev.provider} {ev.channel}".lower()
        if "bits-client" not in provider_context:
            continue
        if ev.event_id not in (3, 59, 60, 61):
            continue

        job_id = (
            ev.event_data.get("Id", "")
            or ev.event_data.get("transferId", "")
            or ev.event_data.get("JobId", "")
            or ev.event_data.get("jobId", "")
            or ev.event_data.get("name", "")
            or ev.event_data.get("jobName", "")
            or ev.event_data.get("jobTitle", "")
            or ev.event_data.get("string", "")
        ).strip()
        if not job_id:
            continue

        key = (ev.computer or "unknown", job_id)
        grouped.setdefault(key, []).append(ev)

    for (_, _), job_events in grouped.items():
        first = min(
            job_events,
            key=lambda item: item.timestamp.isoformat() if item.timestamp else "",
        )
        job_name = ""
        actor = ""
        url_value = ""
        transfer_ids = []
        process_paths = []

        for ev in job_events:
            if not job_name:
                job_name = (
                    ev.event_data.get("jobTitle", "")
                    or ev.event_data.get("jobName", "")
                    or ev.event_data.get("name", "")
                    or ev.event_data.get("string", "")
                    or ""
                ).strip()
            if not actor:
                actor = (
                    ev.event_data.get("jobOwner", "")
                    or ev.event_data.get("string2", "")
                    or ev.logon_user
                    or ev.account_name
                    or ev.domain_user
                    or ev.subject_domain_user
                    or ""
                ).strip()
            if not url_value:
                url_value = (ev.event_data.get("url", "") or ev.event_data.get("RemoteName", "") or "").strip()
            process_path = (ev.event_data.get("processPath", "") or ev.event_data.get("ProcessPath", "") or "").strip()
            if process_path and process_path not in process_paths:
                process_paths.append(process_path)
            transfer_id = (ev.event_data.get("transferId", "") or ev.event_data.get("Id", "") or "").strip()
            if transfer_id and transfer_id not in transfer_ids:
                transfer_ids.append(transfer_id)

        url_lower = url_value.lower()
        remote_url = url_value if url_lower.startswith(("http://", "https://")) else ""
        suspicious_name = _bits_job_name_looks_suspicious(job_name)
        suspicious_path = _is_suspicious_service_payload(url_value)
        suspicious_remote = _bits_remote_url_looks_suspicious(remote_url)

        if not (suspicious_name or suspicious_path or suspicious_remote):
            continue
        if _is_known_benign_bits_job(job_name, remote_url, process_paths):
            continue

        alerts.append(
            Alert(
                rule_name="BITS Client Suspicious Job",
                severity="critical" if (suspicious_name and (suspicious_path or suspicious_remote)) else "high",
                mitre_tactic="Persistence",
                mitre_technique="T1197",
                description=f"BITS client job {job_name or job_events[0].event_data.get('Id', 'unknown')} referenced suspicious content on {first.computer}",
                explanation="Native BITS client operational events can expose background jobs used to stage payloads or execute follow-on content without relying on bitsadmin.exe telemetry. This detector now requires suspicious job metadata, executable-like targets, or non-benign remote transfer patterns rather than treating ordinary update URLs as malicious by default.",
                confidence="high",
                investigate_next="Inspect the BITS job configuration, review the transfer target or executable path, and determine whether the job was used to stage or launch attacker-controlled content.",
                event=first,
                user=actor or "unknown",
                evidence={
                    "job_name": job_name,
                    "actor_user": actor,
                    "url": url_value,
                    "remote_url": remote_url,
                    "process_paths": process_paths,
                    "transfer_ids": transfer_ids,
                    "event_ids": sorted({ev.event_id for ev in job_events}),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _is_sysmon_registry_event(ev: NormalizedEvent) -> bool:
    provider_context = f"{ev.provider} {ev.channel}".lower()
    return "sysmon" in provider_context and ev.event_id in (12, 13)


def _registry_target(ev: NormalizedEvent) -> str:
    return (ev.event_data.get("TargetObject", "") or ev.event_data.get("ObjectName", "") or "").strip()


def _local_sam_username(target: str) -> str:
    clean = (target or "").strip()
    lowered = clean.lower()
    if not lowered.startswith(LOCAL_SAM_NAMES_PREFIX):
        return ""

    remainder = clean[len(LOCAL_SAM_NAMES_PREFIX) :]
    username = remainder.split("\\", 1)[0].strip()
    if username in {"", "(Default)"}:
        return ""
    return username


def _local_sam_account_registry_activity(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if not _is_sysmon_registry_event(ev):
            continue

        target = _registry_target(ev)
        username = _local_sam_username(target)
        if not username:
            continue

        event_type = (ev.event_data.get("EventType", "") or "").strip().lower()
        lowered_target = target.lower()
        is_create = ev.event_id == 12 and event_type == "createkey"
        is_default_set = ev.event_id == 13 and event_type == "setvalue" and lowered_target.endswith(r"\(default)")
        is_delete = ev.event_id == 12 and event_type == "deletekey"
        if not (is_create or is_default_set or is_delete):
            continue

        key = ((ev.computer or "unknown"), username.lower())
        entry = grouped.setdefault(
            key,
            {
                "first_event": ev,
                "paths": set(),
                "create_count": 0,
                "setvalue_count": 0,
                "delete_count": 0,
                "timestamps": [],
            },
        )
        if ev.timestamp and (not entry["first_event"].timestamp or ev.timestamp < entry["first_event"].timestamp):
            entry["first_event"] = ev
        entry["paths"].add(target.split(r"\(Default)", 1)[0].rstrip("\\"))
        entry["timestamps"].append(ev.timestamp.isoformat() if ev.timestamp else None)
        if is_create:
            entry["create_count"] += 1
        elif is_default_set:
            entry["setvalue_count"] += 1
        elif is_delete:
            entry["delete_count"] += 1

    for (host, _), entry in grouped.items():
        if not (entry["create_count"] or entry["setvalue_count"]):
            continue

        first_event = entry["first_event"]
        username = _local_sam_username(next(iter(entry["paths"])))
        registry_paths = sorted(entry["paths"])
        hidden_account = username.endswith("$")
        alerts.append(
            Alert(
                rule_name="Hidden Local Account Registry Entry" if hidden_account else "Local SAM Account Created",
                severity="high",
                mitre_tactic="Defense Evasion" if hidden_account else "Persistence",
                mitre_technique="T1564.002" if hidden_account else "T1136",
                description=(
                    f"Hidden local account {username or 'unknown'} was written into the SAM registry on {host}"
                    if hidden_account
                    else f"Local SAM account {username or 'unknown'} was created via registry activity on {host}"
                ),
                explanation=(
                    "CreateKey and default-value writes under HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names indicate local "
                    "account provisioning at the SAM registry layer. Repeated create/delete churn for the same account is collapsed into one activity."
                    if not hidden_account
                    else "A local SAM account ending in '$' blends in with machine-account naming and is a common hidden-account technique. "
                    "Repeated churn for the same account is collapsed into one registry-backed activity."
                ),
                confidence="low",
                investigate_next=(
                    f"Confirm whether local account {username or '(unknown)'} should exist on {host}, inspect nearby local-group changes, "
                    "and compare the registry activity with local user enumeration and SAM state."
                    if not hidden_account
                    else f"Verify whether hidden-style account {username or '(unknown)'} is present locally, review any paired UserList or group-modification activity, "
                    "and determine whether the account was created for persistence."
                ),
                event=first_event,
                user=username,
                target_user=username,
                process=first_event.process_name,
                registry_key=registry_paths[0] if registry_paths else "",
                evidence={
                    "created_username": username,
                    "registry_paths": registry_paths,
                    "create_count": entry["create_count"],
                    "setvalue_count": entry["setvalue_count"],
                    "delete_count": entry["delete_count"],
                    "collapsed_event_count": entry["create_count"] + entry["setvalue_count"] + entry["delete_count"],
                    "timestamps": entry["timestamps"],
                    "evidence_strength": "medium",
                },
            )
        )

    return alerts


def _specialaccounts_hidden_user_value(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if not _is_sysmon_registry_event(ev) or ev.event_id != 13:
            continue
        if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
            continue

        target = _registry_target(ev)
        lowered = target.lower()
        if not lowered.startswith(SPECIAL_ACCOUNTS_USERLIST_PREFIX):
            continue

        username = target[len(SPECIAL_ACCOUNTS_USERLIST_PREFIX) :].split("\\", 1)[0].strip()
        details = (ev.event_data.get("Details", "") or ev.event_data.get("NewValue", "") or "").strip().lower()
        if username in seen:
            continue
        if details not in {"0", "dword (0x00000000)", "0x00000000"} and "0x00000000" not in details:
            continue

        seen.add(username)
        alerts.append(
            Alert(
                rule_name="Hidden User Registry Value",
                severity="high",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1564.002",
                description=f"Winlogon UserList hid account {username or 'unknown'} on {ev.computer}",
                explanation="SpecialAccounts\\UserList values set to 0 hide local accounts from the logon UI and common account listings.",
                confidence="medium",
                investigate_next="Confirm the account exists locally, inspect how it was created, and review whether it was added to privileged groups or used for interactive logons.",
                event=ev,
                user=username,
                target_user=username,
                process=ev.process_name,
                registry_key=target,
                evidence={
                    "hidden_username": username,
                    "registry_key": target,
                    "details": ev.event_data.get("Details", "") or ev.event_data.get("NewValue", ""),
                    "evidence_strength": "medium",
                },
            )
        )

    return alerts


def _guest_rid_hijack(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()

    for ev in events:
        if not _is_sysmon_registry_event(ev) or ev.event_id != 13:
            continue
        if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
            continue

        target = _registry_target(ev)
        lowered = target.lower()
        if r"\sam\sam\domains\account\users\000001f5\f" not in lowered:
            continue

        process_name = (ev.process_name or "").lower()
        if process_name.endswith("lsass.exe"):
            continue

        key = (ev.computer or "unknown", target.lower(), process_name)
        if key in seen:
            continue
        seen.add(key)

        alerts.append(
            Alert(
                rule_name="Guest RID Hijack",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1098",
                description=f"Guest account RID data was modified on {ev.computer} by {ev.process_name or 'unknown process'}",
                explanation="Modifying the SAM record for RID 501 changes the built-in Guest account profile and can be abused to hijack a valid low-visibility local account.",
                confidence="high",
                investigate_next="Inspect the Guest account SID and group memberships, review the modifying process, and determine whether the Guest account was repurposed for privileged access.",
                event=ev,
                process=ev.process_name,
                registry_key=target,
                evidence={
                    "registry_key": target,
                    "process_image": ev.process_name,
                    "details": ev.event_data.get("Details", "") or ev.event_data.get("NewValue", ""),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _local_admin_alias_modification(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    by_host = {}

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if not _is_sysmon_registry_event(ev):
            continue
        if ev.event_id != 13:
            continue
        if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
            continue

        target = _registry_target(ev)
        if LOCAL_ADMIN_ALIAS_KEY not in target.lower():
            continue
        by_host.setdefault(ev.computer or "unknown", []).append(ev)

    for host, host_events in by_host.items():
        cluster = []
        clusters = []
        for ev in host_events:
            if cluster and ev.timestamp - cluster[-1].timestamp > timedelta(hours=2):
                clusters.append(cluster)
                cluster = []
            cluster.append(ev)
        if cluster:
            clusters.append(cluster)

        for cluster_events in clusters:
            first_event = cluster_events[0]
            alias_paths = sorted({_registry_target(ev) for ev in cluster_events if _registry_target(ev)})
            alerts.append(
                Alert(
                    rule_name="Local Administrators Group Modified",
                    severity="critical",
                    mitre_tactic="Persistence",
                    mitre_technique="T1098",
                    description=f"Local Administrators membership changed in SAM on {host}",
                    explanation=(
                        "SetValue activity on HKLM\\SAM\\SAM\\Domains\\Builtin\\Aliases\\00000220\\C maps to local Administrators "
                        "membership changes and is a strong persistence or privilege-escalation signal."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Enumerate the current local Administrators membership, identify the added account, and compare the SAM alias modification "
                        "timeline with nearby account-creation or remote-execution activity."
                    ),
                    event=first_event,
                    process=first_event.process_name,
                    registry_key=alias_paths[0] if alias_paths else "",
                    evidence={
                        "alias_paths": alias_paths,
                        "modification_count": len(cluster_events),
                        "timestamps": [ev.timestamp.isoformat() if ev.timestamp else None for ev in cluster_events],
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _rapid_user_account_lifecycle(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    creations = {}
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)

    for ev in timed_events:
        if ev.event_id == 4720:
            account_sid = (ev.event_data.get("TargetSid", "") or "").strip()
            account_name = (ev.target_domain_user or ev.target_user or ev.event_data.get("SamAccountName", "") or "").strip().lower()
            key = (ev.computer or "unknown", account_sid or account_name)
            creations[key] = ev
            continue

        if ev.event_id != 4726:
            continue

        account_sid = (ev.event_data.get("TargetSid", "") or "").strip()
        account_name = (ev.target_domain_user or ev.target_user or ev.event_data.get("SamAccountName", "") or "").strip().lower()
        key = (ev.computer or "unknown", account_sid or account_name)
        created = creations.get(key)
        if not created:
            continue

        if ev.timestamp - created.timestamp > timedelta(minutes=15):
            continue

        created_account = created.target_domain_user or created.target_user or created.event_data.get("SamAccountName", "") or "unknown"
        creator = created.subject_domain_user or created.domain_user or "unknown"
        deleter = ev.subject_domain_user or ev.domain_user or "unknown"
        alerts.append(
            Alert(
                rule_name="Rapid User Create/Delete",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1136.001",
                description=f"User {created_account} was created and removed quickly on {created.computer}",
                explanation="Short-lived account creation and deletion can indicate failed backdoor provisioning, testing, or attacker cleanup after account abuse.",
                confidence="high",
                investigate_next="Review the creator and deleter accounts, determine whether the new account ever logged on, and inspect nearby group membership or privilege changes.",
                event=created,
                user=created_account,
                subject_user=creator,
                target_user=created_account,
                evidence={
                    "created_account": created_account,
                    "creator_user": creator,
                    "deleter_user": deleter,
                    "created_timestamp": created.timestamp.isoformat() if created.timestamp else None,
                    "deleted_timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                    "lifetime_seconds": int((ev.timestamp - created.timestamp).total_seconds()),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _new_privileged_account_provisioning(events: List[NormalizedEvent]) -> Tuple[List[Alert], Set[int]]:
    alerts = []
    consumed_event_ids: Set[int] = set()
    creations = []
    additions = []

    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id == 4720:
            account_name = (
                ev.target_domain_user
                or ev.target_user
                or ev.event_data.get("SamAccountName", "")
                or ev.event_data.get("TargetUserName", "")
            ).strip()
            if not account_name:
                continue
            creations.append(ev)
            continue

        if ev.event_id not in (4728, 4732, 4756):
            continue

        group_name = _resolve_group_identity(
            ev.event_data.get("TargetUserName", ""),
            ev.event_data.get("TargetSid", ""),
            ev.event_data.get("TargetDomainName", "") or ev.target_domain,
        )
        if not _is_sensitive_group(group_name):
            continue
        additions.append((ev, group_name))

    seen_keys = set()
    for create in creations:
        created_account = (
            create.target_domain_user
            or create.target_user
            or create.event_data.get("SamAccountName", "")
            or create.event_data.get("TargetUserName", "")
        ).strip()
        if not created_account:
            continue

        target_sid = (create.event_data.get("TargetSid", "") or "").strip()
        create_keys = _identity_keys(created_account, target_sid)
        host = create.computer or "unknown"
        related_additions = []

        for add, group_name in additions:
            if (add.computer or "unknown") != host:
                continue
            if add.timestamp < create.timestamp or add.timestamp - create.timestamp > timedelta(hours=1):
                continue
            member_name = _resolve_member_identity(add.event_data.get("MemberName", ""), add.event_data.get("MemberSid", ""))
            member_keys = _identity_keys(member_name, add.event_data.get("MemberSid", ""))
            if create_keys.isdisjoint(member_keys):
                continue
            related_additions.append((add, group_name))

        if not related_additions:
            continue

        dedupe_key = (host, target_sid.lower() or created_account.lower())
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        creator = create.subject_domain_user or create.domain_user or "unknown"
        group_changers = sorted(
            {
                (add.subject_domain_user or add.domain_user or "unknown").strip() or "unknown"
                for add, _ in related_additions
            }
        )
        sensitive_groups = sorted({group_name for _, group_name in related_additions if group_name})
        addition_times = [add.timestamp.isoformat() if add.timestamp else None for add, _ in related_additions]
        addition_ids = [add.event_id for add, _ in related_additions]

        alerts.append(
            Alert(
                rule_name="New Privileged Account Provisioned",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1136.001",
                description=f"New account '{created_account}' was created and granted privileged group membership on {host}",
                explanation=(
                    "An account was created and then added to a sensitive group shortly afterward. This combination is a much stronger persistence story "
                    "than either event alone and often indicates deliberate privileged backdoor provisioning."
                ),
                confidence="high",
                investigate_next=(
                    "Validate whether the new account and privileged group membership were authorized, review logons for the new account, and inspect surrounding "
                    "administration or persistence activity on the host."
                ),
                event=create,
                user=created_account,
                subject_user=creator,
                target_user=created_account,
                evidence={
                    "new_account": created_account,
                    "target_sid": target_sid,
                    "created_by": creator,
                    "group_change_actors": group_changers,
                    "sensitive_groups": sensitive_groups,
                    "group_event_ids": addition_ids,
                    "group_add_timestamps": addition_times,
                    "created_timestamp": create.timestamp.isoformat() if create.timestamp else None,
                    "collapsed_event_count": 1 + len(related_additions),
                    "evidence_strength": "high",
                },
            )
        )

        consumed_event_ids.add(id(create))
        consumed_event_ids.update(id(add) for add, _ in related_additions)

    return alerts, consumed_event_ids


def _fake_computer_account_creation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped = {}

    for ev in sorted(events, key=lambda item: (item.timestamp is None, item.timestamp.isoformat() if item.timestamp else "")):
        if ev.event_id != 4720:
            continue

        sam_account = (ev.event_data.get("SamAccountName", "") or ev.target_user or "").strip()
        if not sam_account.endswith("$"):
            continue

        host = ev.computer or "unknown"
        key = (host, sam_account.lower())
        entry = grouped.setdefault(key, [])
        if entry and ev.timestamp and entry[-1][-1].timestamp and ev.timestamp - entry[-1][-1].timestamp > timedelta(hours=2):
            entry.append([ev])
        elif entry:
            entry[-1].append(ev)
        else:
            entry.append([ev])

    for (_, _), clusters in grouped.items():
        for cluster in clusters:
            first_event = cluster[0]
            sam_account = (first_event.event_data.get("SamAccountName", "") or first_event.target_user or "").strip() or "unknown"
            created_account = first_event.target_domain_user or sam_account
            created_by_users = sorted(
                {
                    (ev.subject_domain_user or ev.subject_user or "unknown").strip() or "unknown"
                    for ev in cluster
                }
            )
            target_sids = sorted(
                {
                    (ev.event_data.get("TargetSid", "") or "").strip()
                    for ev in cluster
                    if (ev.event_data.get("TargetSid", "") or "").strip()
                }
            )
            alerts.append(
                Alert(
                    rule_name="Fake Computer Account Created",
                    severity="high",
                    mitre_tactic="Persistence",
                    mitre_technique="T1136.001",
                    description=f"Computer-like account '{sam_account}' created on {first_event.computer}",
                    explanation="User account creation via Event 4720 with a trailing '$' mimics a machine account name and is commonly used to hide persistence or confuse responders. Repeated creation churn for the same fake computer-style account is collapsed into one activity.",
                    confidence="high",
                    investigate_next=f"Verify whether '{sam_account}' should exist, inspect who created it, and review whether it was granted privileges or used for logons.",
                    event=first_event,
                    user=created_account,
                    subject_user=created_by_users[0] if len(created_by_users) == 1 else first_event.subject_domain_user or first_event.subject_user or "unknown",
                    target_user=created_account,
                    evidence={
                        "new_account": sam_account,
                        "created_by": created_by_users[0] if len(created_by_users) == 1 else created_by_users,
                        "target_sid": target_sids[0] if len(target_sids) == 1 else "",
                        "target_sids": target_sids,
                        "user_account_control": first_event.event_data.get("UserAccountControl", ""),
                        "collapsed_event_count": len(cluster),
                        "timestamps": [ev.timestamp.isoformat() if ev.timestamp else None for ev in cluster],
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _guest_account_enabled(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    for ev in events:
        if ev.event_id != 4722:
            continue

        target_user = (ev.target_domain_user or ev.target_user or ev.event_data.get("TargetUserName", "") or "").strip()
        if not target_user or "guest" not in target_user.lower():
            continue

        actor = ev.subject_domain_user or ev.domain_user or "unknown"
        alerts.append(
            Alert(
                rule_name="Guest Account Enabled",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1136.001",
                description=f"{actor} enabled the Guest account on {ev.computer}",
                explanation="Re-enabling the built-in Guest account can provide a low-friction backdoor account that blends in with default local identities.",
                confidence="high",
                investigate_next="Verify whether Guest should ever be enabled on this system, inspect subsequent logons for the account, and review nearby group membership changes.",
                event=ev,
                user=target_user,
                subject_user=actor,
                target_user=target_user,
                evidence={
                    "actor_user": actor,
                    "target_user": target_user,
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _resolve_member_identity(member_name: str, member_sid: str) -> str:
    member = (member_name or "").strip()
    if member and member != "-":
        return member

    sid = (member_sid or "").strip()
    sid_lower = sid.lower()
    if sid_lower in WELL_KNOWN_MEMBER_SIDS:
        return WELL_KNOWN_MEMBER_SIDS[sid_lower]
    if sid.endswith("-501"):
        return "Guest"
    return sid


def _rapid_local_group_membership_churn(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    additions = [
        ev for ev in events
        if ev.event_id == 4732 and ev.timestamp
    ]
    removals = [
        ev for ev in events
        if ev.event_id == 4733 and ev.timestamp
    ]

    for add in additions:
        member = _resolve_member_identity(add.event_data.get("MemberName", ""), add.event_data.get("MemberSid", ""))
        group = add.target_domain_user or add.event_data.get("TargetUserName", "") or "unknown"
        actor = add.subject_domain_user or add.domain_user or "unknown"
        host = add.computer or "unknown"
        logon_id = add.event_data.get("SubjectLogonId", "")

        for remove in removals:
            if (remove.computer or "") != host:
                continue
            if (remove.target_domain_user or remove.event_data.get("TargetUserName", "") or "") != group:
                continue
            removed_member = _resolve_member_identity(remove.event_data.get("MemberName", ""), remove.event_data.get("MemberSid", ""))
            if removed_member != member:
                continue
            if logon_id and remove.event_data.get("SubjectLogonId", "") not in {"", logon_id}:
                continue
            if remove.timestamp < add.timestamp or remove.timestamp - add.timestamp > timedelta(minutes=15):
                continue

            sensitive = any(token in group.lower() for token in ("administrators", "backup operators", "dnsadmins"))
            alerts.append(
                Alert(
                    rule_name="Rapid Local Group Membership Churn",
                    severity="critical" if sensitive else "high",
                    mitre_tactic="Persistence",
                    mitre_technique="T1098",
                    description=f"{member} was added to and removed from {group} on {host} in quick succession",
                    explanation="Fast add/remove activity in local privileged groups can indicate permission staging, short-lived privilege escalation, or attacker cleanup.",
                    confidence="high" if sensitive else "medium",
                    investigate_next="Review who performed the group change, determine whether the member authenticated during the elevated window, and inspect nearby persistence or execution events.",
                    event=add,
                    user=member,
                    subject_user=actor,
                    target_user=member,
                    evidence={
                        "member": member,
                        "group": group,
                        "actor_user": actor,
                        "added_timestamp": add.timestamp.isoformat() if add.timestamp else None,
                        "removed_timestamp": remove.timestamp.isoformat() if remove.timestamp else None,
                        "lifetime_seconds": int((remove.timestamp - add.timestamp).total_seconds()),
                        "evidence_strength": "high" if sensitive else "medium",
                    },
                )
            )
            break

    return alerts


def _directory_attribute_name(ev: NormalizedEvent) -> str:
    return _first_present(ev.event_data, "AttributeLDAPDisplayName", "AttributeName", "LDAPDisplayName", "Attribute")


def _directory_object_dn(ev: NormalizedEvent) -> str:
    return _first_present(ev.event_data, "ObjectDN", "ObjectName", "DistinguishedName", "TargetObject")


def _event_blob(ev: NormalizedEvent) -> str:
    parts = [str(value or "") for value in (ev.event_data or {}).values()]
    if ev.raw_xml:
        parts.append(ev.raw_xml)
    return " ".join(parts)


def _embedded_eventdata_text(ev: NormalizedEvent) -> str:
    if not ev.raw_xml:
        return ""
    match = re.search(r"<Data>(.*?)</Data>", ev.raw_xml, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    text = html.unescape(match.group(1))
    text = re.sub(r"</?string>", "", text, flags=re.IGNORECASE)
    return text.strip()


def _embedded_eventdata_map(ev: NormalizedEvent) -> Dict[str, str]:
    payload = {}
    for line in _embedded_eventdata_text(ev).splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        payload[key.strip().lower()] = value.strip()
    return payload


def _extract_cn_from_dn(value: str) -> str:
    match = re.search(r"CN=([^,]+)", value or "", re.IGNORECASE)
    return (match.group(1) or "").strip() if match else ""


def _normalize_identity(value: str) -> str:
    text = (value or "").strip().lower()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    return text


def _safe_int(value: str) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _normalized_account_key(value: str) -> str:
    text = _normalize_identity(value)
    return text[:-1] if text.endswith("$") else text


def _normalized_principal_key(value: str) -> str:
    text = _normalize_identity(value)
    if "@" in text:
        text = text.split("@", 1)[0]
    return text[:-1] if text.endswith("$") else text


def _delegation_flags_added(old_val: int | None, new_val: int | None) -> List[str]:
    if old_val is None or new_val is None:
        return []
    added_flags = []
    if (old_val & 0x80000) == 0 and (new_val & 0x80000) != 0:
        added_flags.append("TrustedForDelegation")
    if (old_val & 0x1000000) == 0 and (new_val & 0x1000000) != 0:
        added_flags.append("TrustedToAuthForDelegation")
    return added_flags


def _parse_setspn_add_command(command: str) -> Tuple[str, str] | None:
    match = SETSPN_ADD_RE.search(command or "")
    if not match:
        return None
    spn_value = (match.group(1) or match.group(2) or "").strip().strip("\"'")
    target = (match.group(3) or match.group(4) or "").strip().strip("\"'")
    if not spn_value or not target or "/" not in spn_value:
        return None
    return spn_value, target


def _is_privileged_reset_target(target: str, target_sid: str) -> bool:
    simple = _normalize_identity(target)
    sid = (target_sid or "").strip().lower()
    return simple in {"administrator", "krbtgt"} or sid.endswith("-500") or sid.endswith("-502")


def _normalize_uac_text(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).lower()


def _uac_flag_matches(value: str, phrases: Tuple[str, ...], tokens: Tuple[str, ...]) -> bool:
    normalized = _normalize_uac_text(value)
    if not normalized or normalized == "-":
        return False
    return any(token.lower() in normalized for token in tokens) or any(phrase in normalized for phrase in phrases)


def _is_admin_like_name(value: str) -> bool:
    normalized = _normalize_identity(value)
    return normalized.startswith("admin") or "administrator" in normalized or bool(ADMIN_LIKE_NAME_RE.search(normalized))


def _cross_account_password_change(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 4723:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue

        actor = ev.subject_domain_user or ev.subject_user or ""
        target = ev.target_domain_user or ev.target_user or ""
        if not actor or not target:
            continue
        if _normalize_identity(actor) == _normalize_identity(target):
            continue
        if _normalize_identity(actor).endswith("$"):
            continue

        subject_logon_id = _first_present(ev.event_data, "SubjectLogonId", "LogonId")
        key = (ev.computer or "", _normalize_identity(actor), _normalize_identity(target), subject_logon_id)
        if key in seen:
            continue
        seen.add(key)

        alerts.append(Alert(
            rule_name="Cross-Account Password Change",
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor} changed the password for {target} on {ev.computer}",
            explanation="Event 4723 normally reflects a user changing their own password. When one account changes another account's password, it is consistent with account manipulation such as NTLM credential replacement or unauthorized credential takeover.",
            confidence="high",
            investigate_next="Validate the password change with both account owners, review follow-on logons for the modified account, and rotate the credential if the change was not authorized.",
            event=ev,
            user=target,
            subject_user=actor,
            target_user=target,
            evidence={
                "actor_user": actor,
                "target_user": target,
                "target_sid": _first_present(ev.event_data, "TargetSid"),
                "subject_logon_id": subject_logon_id,
                "evidence_strength": "high",
            },
        ))
    return alerts


def _new_smb_share_added(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str], Dict[str, object]] = {}

    for ev in events:
        if ev.event_id not in (12, 13):
            continue
        provider = (ev.provider or "").lower()
        channel = (ev.channel or "").lower()
        if "sysmon" not in provider and "sysmon" not in channel:
            continue

        target_object = (ev.event_data.get("TargetObject", "") or "").strip()
        target_object_l = target_object.lower()
        if not target_object_l.startswith(LANMANSERVER_SHARES_PREFIX):
            continue

        share_segment = target_object[len(LANMANSERVER_SHARES_PREFIX):].strip("\\")
        if not share_segment:
            continue
        share_name = share_segment.split("\\")[-1].strip()
        if not share_name:
            continue
        if share_name.lower() in {"c$", "admin$", "ipc$", "print$", "sysvol", "netlogon"}:
            continue

        key = (ev.computer or "unknown", share_name.lower())
        entry = grouped.setdefault(
            key,
            {
                "events": [],
                "paths": set(),
                "security_paths": set(),
                "share_name": share_name,
            },
        )
        entry["events"].append(ev)
        entry["paths"].add(target_object)
        if "\\shares\\security\\" in target_object_l:
            entry["security_paths"].add(target_object)

    for (host, _), entry in grouped.items():
        cluster = sorted(entry["events"], key=lambda item: item.timestamp.isoformat() if item.timestamp else "")
        if not cluster:
            continue
        if len(entry["paths"]) < 2 and not entry["security_paths"]:
            continue

        first = cluster[0]
        image = first.event_data.get("Image", "") or first.process_name or ""
        alerts.append(
            Alert(
                rule_name="New SMB Share Added",
                severity="high",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1021.002",
                description=f"Share {entry['share_name']} was added on {host}",
                explanation="Sysmon registry events under LanmanServer\\Shares show a new SMB share definition and security entry, which can be used to stage files or expose a remote-access foothold.",
                confidence="high",
                investigate_next="Validate whether the share was intentionally created, inspect the exposed path and permissions, and review nearby remote file copy or service-execution activity involving the same host.",
                event=first,
                user="unknown",
                process=image,
                evidence={
                    "share_name": entry["share_name"],
                    "target_objects": sorted(entry["paths"]),
                    "security_objects": sorted(entry["security_paths"]),
                    "image": image,
                    "modification_count": len(cluster),
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _account_control_flag_changes(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 4738:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue

        actor = ev.subject_domain_user or ev.subject_user or ""
        target = ev.target_domain_user or ev.target_user or ""
        if not target:
            continue
        if _normalize_identity(actor).endswith("$"):
            continue

        user_account_control = _first_present(ev.event_data, "UserAccountControl")
        normalized_uac = _normalize_uac_text(user_account_control)
        if not normalized_uac or normalized_uac == "-":
            continue

        for rule in ACCOUNT_CONTROL_UAC_RULES:
            if not _uac_flag_matches(user_account_control, rule["phrases"], rule["tokens"]):
                continue

            key = (ev.computer or "", _normalize_identity(target), _normalize_identity(actor), rule["title"])
            if key in seen:
                continue
            seen.add(key)

            matched_tokens = [token for token in rule["tokens"] if token.lower() in normalized_uac]
            alerts.append(Alert(
                rule_name=rule["title"],
                severity=rule["severity"],
                mitre_tactic="Persistence",
                mitre_technique=rule["mitre_technique"],
                description=f"{actor or 'Unknown actor'} {rule['summary']} for {target} on {ev.computer}",
                explanation=rule["explanation"],
                confidence="high",
                investigate_next=rule["investigate_next"],
                event=ev,
                user=target,
                subject_user=actor,
                target_user=target,
                evidence={
                    "actor_user": actor or "unknown",
                    "target_user": target,
                    "old_uac_value": _first_present(ev.event_data, "OldUacValue", "OldValue", "PreviousValue"),
                    "new_uac_value": _first_present(ev.event_data, "NewUacValue", "NewValue", "Value"),
                    "user_account_control": user_account_control.strip(),
                    "uac_tokens": matched_tokens,
                    "subject_logon_id": _first_present(ev.event_data, "SubjectLogonId", "LogonId"),
                    "evidence_strength": "high",
                },
            ))
            break
    return alerts


def _account_rename_manipulation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 4781:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue

        actor = ev.subject_domain_user or ev.subject_user or ""
        if _normalize_identity(actor).endswith("$"):
            continue

        old_name = _first_present(ev.event_data, "OldTargetUserName", "OldSamAccountName").strip()
        new_name = _first_present(ev.event_data, "NewTargetUserName", "NewSamAccountName", "TargetUserName").strip()
        if not old_name or not new_name or old_name.lower() == new_name.lower():
            continue

        target_domain = _first_present(ev.event_data, "TargetDomainName").strip()
        target_account = f"{target_domain}\\{new_name}" if target_domain and "\\" not in new_name else new_name
        target_sid = _first_present(ev.event_data, "TargetSid")
        subject_logon_id = _first_present(ev.event_data, "SubjectLogonId", "LogonId")

        if old_name.endswith("$") and not new_name.endswith("$"):
            spoofing_follow_on = _samaccount_spoofing_follow_on(events, ev, new_name)
            if spoofing_follow_on:
                key = (ev.computer or "", target_sid or new_name.lower(), "computer_account_spoofing_kerberos_abuse")
                if key in seen:
                    continue
                seen.add(key)
                alerts.append(Alert(
                    rule_name="Computer Account Spoofing Kerberos Abuse",
                    severity="critical",
                    mitre_tactic="Persistence",
                    mitre_technique="T1098",
                    description=(
                        f"{actor or 'Unknown actor'} renamed computer account {old_name} to {new_name} on {ev.computer} "
                        f"and immediately used Kerberos tickets consistent with sAMAccountName spoofing abuse"
                    ),
                    explanation=(
                        "A computer account was renamed to remove the trailing '$' and then immediately used in Kerberos "
                        "AS-REQ and service-ticket activity for the spoofed machine identity. This sequence is strongly "
                        "consistent with sAMAccountName spoofing / noPac-style Kerberos abuse."
                    ),
                    confidence="high",
                    investigate_next=(
                        "Isolate the affected domain controller or host, restore the spoofed computer account name, review "
                        "all Kerberos tickets requested from the same source, and inspect follow-on privileged logons or "
                        "directory changes tied to the spoofed identity."
                    ),
                    event=ev,
                    user=target_account,
                    subject_user=actor,
                    target_user=target_account,
                    source_ip=spoofing_follow_on["primary_source_ip"],
                    evidence={
                        "old_name": old_name,
                        "new_name": new_name,
                        "target_sid": target_sid,
                        "subject_logon_id": subject_logon_id,
                        "source_ips": spoofing_follow_on["source_ips"],
                        "service_names": spoofing_follow_on["service_names"],
                        "as_req_count": spoofing_follow_on["as_req_count"],
                        "service_ticket_count": spoofing_follow_on["service_ticket_count"],
                        "rename_revert_count": spoofing_follow_on["rename_revert_count"],
                        "machine_logon_count": spoofing_follow_on["machine_logon_count"],
                        "evidence_strength": "high",
                    },
                ))
                continue

            key = (ev.computer or "", target_sid or new_name.lower(), "computer_account_rename_without_trailing_dollar")
            if key in seen:
                continue
            seen.add(key)
            alerts.append(Alert(
                rule_name="Computer Account Renamed Without Trailing Dollar",
                severity="critical",
                mitre_tactic="Persistence",
                mitre_technique="T1098",
                description=f"{actor or 'Unknown actor'} renamed computer account {old_name} to {new_name} on {ev.computer}",
                explanation="Renaming a computer account to remove the trailing '$' is consistent with sAMAccountName spoofing techniques such as CVE-2021-42278 abuse.",
                confidence="high",
                investigate_next="Check whether the renamed computer account was used for Kerberos requests, restore the original name immediately, and review any follow-on DC impersonation activity.",
                event=ev,
                user=target_account,
                subject_user=actor,
                target_user=target_account,
                evidence={
                    "old_name": old_name,
                    "new_name": new_name,
                    "target_sid": target_sid,
                    "subject_logon_id": subject_logon_id,
                    "evidence_strength": "high",
                },
            ))
            continue

        old_norm = _normalize_identity(old_name)
        new_norm = _normalize_identity(new_name)
        if not _is_admin_like_name(new_name) or _is_admin_like_name(old_name):
            continue

        key = (ev.computer or "", target_sid or new_norm, "user_renamed_admin_like")
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name="User Renamed to Admin-Like Name",
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor or 'Unknown actor'} renamed account {old_name} to {new_name} on {ev.computer}",
            explanation="Renaming a non-administrative account to an admin-like name can help it blend in with privileged identities and confuse investigators.",
            confidence="high",
            investigate_next="Verify whether the rename was approved, inspect group memberships and logons for the renamed account, and confirm whether the new name is meant to resemble a privileged identity.",
            event=ev,
            user=target_account,
            subject_user=actor,
            target_user=target_account,
            evidence={
                "old_name": old_name,
                "new_name": new_name,
                "target_sid": target_sid,
                "subject_logon_id": subject_logon_id,
                "evidence_strength": "high",
            },
        ))
    return alerts


def _samaccount_spoofing_follow_on(
    events: List[NormalizedEvent],
    rename_event: NormalizedEvent,
    new_name: str,
) -> Dict[str, object] | None:
    if not rename_event.timestamp:
        return None

    spoofed_name = _normalized_principal_key(new_name)
    if not spoofed_name:
        return None

    window_end = rename_event.timestamp + timedelta(minutes=5)
    as_reqs: List[NormalizedEvent] = []
    service_tickets: List[NormalizedEvent] = []
    rename_reverts: List[NormalizedEvent] = []
    machine_logons: List[NormalizedEvent] = []

    for other in events:
        if other is rename_event or not other.timestamp:
            continue
        if other.timestamp < rename_event.timestamp or other.timestamp > window_end:
            continue
        if not ((other.provider or "").lower().find("security") >= 0 or (other.channel or "").lower() == "security"):
            continue

        if other.event_id == 4768:
            principal = _normalized_principal_key(
                _first_present(other.event_data, "TargetUserName", "AccountName")
                or other.target_domain_user
                or other.target_user
                or other.user
            )
            service_name = _normalized_principal_key(_first_present(other.event_data, "ServiceName") or other.service_name)
            if principal == spoofed_name and service_name == "krbtgt":
                as_reqs.append(other)
            continue

        if other.event_id == 4769:
            principal = _normalized_principal_key(
                _first_present(other.event_data, "TargetUserName", "AccountName")
                or other.target_domain_user
                or other.target_user
                or other.user
            )
            service_name = _normalized_principal_key(_first_present(other.event_data, "ServiceName") or other.service_name)
            if principal == spoofed_name and service_name == spoofed_name:
                service_tickets.append(other)
            continue

        if other.event_id == 4781:
            reverted_from = _normalized_principal_key(_first_present(other.event_data, "OldTargetUserName", "OldSamAccountName"))
            reverted_to = _normalized_principal_key(_first_present(other.event_data, "NewTargetUserName", "NewSamAccountName", "TargetUserName"))
            if reverted_from == spoofed_name and reverted_to and reverted_to != spoofed_name:
                rename_reverts.append(other)
            continue

        if other.event_id == 4624:
            principal = _normalized_principal_key(
                _first_present(other.event_data, "TargetUserName", "AccountName")
                or other.target_domain_user
                or other.target_user
                or other.user
            )
            if principal == spoofed_name:
                machine_logons.append(other)

    if not as_reqs or not service_tickets:
        return None

    source_ips = sorted(
        {
            (
                other.source_ip
                or _first_present(other.event_data, "IpAddress", "ClientAddress")
            ).strip()
            for other in [*as_reqs, *service_tickets]
            if (
                other.source_ip
                or _first_present(other.event_data, "IpAddress", "ClientAddress")
            ).strip()
            not in {"", "-"}
        }
    )
    service_names = sorted(
        {
            (_first_present(other.event_data, "ServiceName") or other.service_name or "").strip()
            for other in service_tickets
            if (_first_present(other.event_data, "ServiceName") or other.service_name or "").strip()
        }
    )

    return {
        "primary_source_ip": source_ips[0] if source_ips else "",
        "source_ips": source_ips,
        "service_names": service_names,
        "as_req_count": len(as_reqs),
        "service_ticket_count": len(service_tickets),
        "rename_revert_count": len(rename_reverts),
        "machine_logon_count": len(machine_logons),
    }


def _member_display_name(member_name: str, member_sid: str) -> str:
    extracted = _extract_cn_from_dn(member_name)
    if extracted:
        return extracted
    return _resolve_member_identity(member_name, member_sid)


def _sql_role_membership_changes(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 33205:
            continue
        provider = (ev.provider or "").lower()
        if "mssql" not in provider:
            continue

        payload = _embedded_eventdata_map(ev)
        if not payload:
            continue

        statement = payload.get("statement", "")
        statement_upper = statement.upper()
        actor = payload.get("session_server_principal_name", "") or payload.get("server_principal_name", "") or "unknown"
        target = payload.get("target_server_principal_name", "") or payload.get("object_name", "") or "unknown"
        instance = payload.get("server_instance_name", "") or ev.computer or "unknown instance"
        database_name = payload.get("database_name", "") or ""
        object_name = payload.get("object_name", "") or ""

        if "ALTER SERVER ROLE" in statement_upper and "ADD MEMBER" in statement_upper:
            rule_name = "SQL Server Role Membership Added"
            severity = "critical" if object_name.lower() in {"sysadmin", "securityadmin"} else "high"
            description = f"{actor} added {target} to SQL Server role {object_name or 'unknown role'} on {instance}"
            explanation = "Adding a login to a SQL Server fixed server role can grant durable administrative control over the database engine."
            investigate_next = "Review whether the login should hold that server role, inspect recent SQL logins from the principal, and remove the role assignment if it was not approved."
            evidence = {
                "actor_user": actor,
                "target_principal": target,
                "role_name": object_name,
                "server_instance": instance,
                "database_name": database_name,
                "statement": statement,
                "evidence_strength": "high",
            }
            incident_user = target
        elif "ALTER ROLE" in statement_upper and "ADD MEMBER" in statement_upper:
            rule_name = "SQL Database Role Membership Added"
            severity = "high"
            description = f"{actor} added {target} to database role {object_name or 'unknown role'} in {database_name or 'an unknown database'} on {instance}"
            explanation = "Adding a principal to a SQL database role can create application-level persistence or quietly expand access inside a targeted database."
            investigate_next = "Validate whether the login should be a member of that database role, review recent activity in the database, and remove the assignment if it was unauthorized."
            evidence = {
                "actor_user": actor,
                "target_principal": target,
                "role_name": object_name,
                "server_instance": instance,
                "database_name": database_name,
                "statement": statement,
                "evidence_strength": "high",
            }
            incident_user = target
        elif "CREATE USER" in statement_upper and "FOR LOGIN" in statement_upper:
            rule_name = "SQL User Linked to Login"
            severity = "high"
            description = f"{actor} linked SQL user {object_name or 'unknown user'} to a login in {database_name or 'an unknown database'} on {instance}"
            explanation = "Creating a database user for an existing login can establish or restore application-level access without touching the underlying Windows account directly."
            investigate_next = "Confirm whether the linked SQL user is expected, inspect granted database roles, and review recent SQL authentication and statement history for that login."
            evidence = {
                "actor_user": actor,
                "target_principal": object_name,
                "server_instance": instance,
                "database_name": database_name,
                "statement": statement,
                "evidence_strength": "high",
            }
            incident_user = object_name or target
        else:
            continue

        key = (instance.lower(), rule_name, (statement or "").lower())
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name=rule_name,
            severity=severity,
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=description,
            explanation=explanation,
            confidence="high",
            investigate_next=investigate_next,
            event=ev,
            user=incident_user,
            subject_user=actor,
            target_user=incident_user,
            evidence=evidence,
        ))
    return alerts


def _mass_group_membership_change(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = {}
    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (4728, 4756):
            continue
        actor = ev.subject_domain_user or ev.subject_user or ""
        member = _member_display_name(ev.event_data.get("MemberName", ""), ev.event_data.get("MemberSid", ""))
        if not actor or not member:
            continue
        key = (ev.computer or "unknown", _normalize_identity(actor), _normalize_identity(member))
        grouped.setdefault(key, []).append(ev)

    for (host, _, _), cluster_events in grouped.items():
        if len(cluster_events) < 5:
            continue
        groups = []
        actor = cluster_events[0].subject_domain_user or cluster_events[0].subject_user or "unknown"
        member = _member_display_name(cluster_events[0].event_data.get("MemberName", ""), cluster_events[0].event_data.get("MemberSid", ""))
        for ev in cluster_events:
            group = _resolve_group_identity(
                ev.event_data.get("TargetUserName", ""),
                ev.event_data.get("TargetSid", ""),
                ev.event_data.get("TargetDomainName", "") or ev.target_domain,
            )
            if group and group not in groups:
                groups.append(group)
        if len(groups) < 5:
            continue
        severity = "critical" if len(groups) >= 10 or any(_is_sensitive_group(group) for group in groups) else "high"
        alerts.append(Alert(
            rule_name="Mass Group Membership Change",
            severity=severity,
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor} added {member} to {len(groups)} groups on {host}",
            explanation="Adding the same account to many groups in rapid succession is a strong sign of broad account-manipulation or privilege-staging activity.",
            confidence="high",
            investigate_next="Validate whether the memberships were bulk-provisioned intentionally, review which groups confer privileged access, and remove any unauthorized additions.",
            event=cluster_events[0],
            user=member,
            subject_user=actor,
            target_user=member,
            evidence={
                "actor_user": actor,
                "member": member,
                "groups": groups,
                "group_count": len(groups),
                "subject_logon_id": _first_present(cluster_events[0].event_data, "SubjectLogonId", "LogonId"),
                "timestamps": [ev.timestamp.isoformat() if ev.timestamp else None for ev in cluster_events],
                "evidence_strength": "high",
            },
        ))
    return alerts


def _self_added_to_group(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id not in (4728, 4732, 4756):
            continue
        actor = ev.subject_domain_user or ev.subject_user or ""
        actor_sid = _first_present(ev.event_data, "SubjectUserSid")
        member = _member_display_name(ev.event_data.get("MemberName", ""), ev.event_data.get("MemberSid", ""))
        member_sid = _first_present(ev.event_data, "MemberSid")
        if not actor or not member:
            continue
        if _normalize_identity(actor) != _normalize_identity(member) and actor_sid.lower() != member_sid.lower():
            continue
        group = _resolve_group_identity(
            ev.event_data.get("TargetUserName", ""),
            ev.event_data.get("TargetSid", ""),
            ev.event_data.get("TargetDomainName", "") or ev.target_domain,
        )
        if not group:
            continue
        key = (ev.computer or "", _normalize_identity(actor), group.lower())
        if key in seen:
            continue
        seen.add(key)
        sensitive = _is_sensitive_group(group)
        alerts.append(Alert(
            rule_name="Self-Added to Group",
            severity="critical" if sensitive else "high",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor} added themselves to {group} on {ev.computer}",
            explanation="Self-service addition into a group is unusual administrative behavior and can indicate unauthorized privilege staging or persistence.",
            confidence="high",
            investigate_next="Confirm whether the actor was allowed to modify their own group memberships, review the group's privileges, and remove the membership if it was not approved.",
            event=ev,
            user=member,
            subject_user=actor,
            target_user=member,
            evidence={
                "actor_user": actor,
                "member": member,
                "group": group,
                "subject_logon_id": _first_present(ev.event_data, "SubjectLogonId", "LogonId"),
                "evidence_strength": "high",
            },
        ))
    return alerts


def _shadow_credentials_modified(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 5136:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        attr = (_directory_attribute_name(ev) or "").strip().lower()
        if attr != SHADOW_CREDENTIAL_ATTRIBUTE:
            continue
        object_dn = _directory_object_dn(ev)
        target = _extract_cn_from_dn(object_dn) or ev.target_domain_user or ev.target_user or object_dn
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        key = (ev.computer or "", object_dn.lower(), actor.lower())
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name="Shadow Credentials Modified",
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"Key credential link modified for {target or 'unknown object'} on {ev.computer}",
            explanation="Changing msDS-KeyCredentialLink can register shadow credentials and enable certificate-based logon without the account password.",
            confidence="high",
            investigate_next="Validate the actor, dump the current key credential entries, and remove unauthorized values immediately.",
            event=ev,
            user=target,
            subject_user=actor,
            evidence={
                "object_dn": object_dn,
                "attribute": attr,
                "operation_type": _first_present(ev.event_data, "OperationType", "OpCorrelationID"),
                "evidence_strength": "high",
            },
        ))
    return alerts


def _adcs_suspicious_certificate_request(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id not in (4886, 4887, 4888):
            continue
        body = _event_blob(ev)
        low = body.lower()
        requester = _first_present(ev.event_data, "Requester", "RequesterName", "SubjectUserName", "RequesterAccount") or ev.subject_domain_user or ev.domain_user
        subject = _first_present(ev.event_data, "Subject", "SubjectName", "RequestSubject", "CertificateSubject")
        san_target = ""
        match = ADCS_SAN_RE.search(body)
        if match:
            san_target = (match.group(1) or "").strip()
        template = _first_present(ev.event_data, "CertificateTemplate", "Template", "TemplateName")
        requester_norm = _normalize_identity(requester)
        subject_norm = _normalize_identity(subject or san_target)
        has_san_override = any(token in low for token in ("san:", "upn=", "dns="))
        mismatched_subject = bool(subject_norm and requester_norm and subject_norm != requester_norm)
        if not has_san_override and not mismatched_subject:
            continue
        key = (ev.computer or "", requester_norm, subject_norm or san_target.lower(), template.lower())
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name="AD CS Suspicious Certificate Request",
            severity="critical" if has_san_override and mismatched_subject else "high",
            mitre_tactic="Credential Access",
            mitre_technique="T1649",
            description=f"Certificate request on {ev.computer} used alternate subject data for template {template or 'unknown'}",
            explanation="Certificate enrollment with SAN or subject override can be abused to mint authentication certificates for another identity.",
            confidence="high" if mismatched_subject else "medium",
            investigate_next="Review the full request, identify who approved it, and revoke the issued certificate if the subject does not match the requester.",
            event=ev,
            user=subject or san_target or requester,
            subject_user=requester,
            evidence={
                "template": template,
                "requester": requester,
                "subject": subject,
                "san_target": san_target,
                "request_id": _first_present(ev.event_data, "RequestID", "RequestId", "SerialNumber"),
                "evidence_strength": "high" if mismatched_subject else "medium",
            },
        ))
    return alerts


def _adcs_vulnerable_template_change(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id not in (4898, 4899, 4900):
            continue
        body = _event_blob(ev)
        low = body.lower()
        if not all(marker in low for marker in ("enrollee", "subject")):
            continue
        if not any(marker in low for marker in ("client authentication", "certificate request agent", "any purpose", "ct_flag_enrollee_supplies_subject")):
            continue
        template = _first_present(ev.event_data, "Template", "TemplateName", "CertificateTemplate") or _extract_cn_from_dn(_directory_object_dn(ev))
        key = (ev.computer or "", template.lower(), ev.event_id)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name="AD CS Vulnerable Template Change",
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1649",
            description=f"Certificate template {template or 'unknown'} was made enrollment-dangerous on {ev.computer}",
            explanation="A certificate template was changed to allow subject-supplied requests with authentication-capable EKUs, a common precursor to AD CS abuse.",
            confidence="high",
            investigate_next="Compare the template against a known-good baseline, roll back unsafe settings, and review recent certificate issuance from this template.",
            event=ev,
            evidence={
                "template": template,
                "event_id": ev.event_id,
                "evidence_strength": "high",
            },
        ))
    return alerts


def _delegation_configuration_changed(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    direct_attr_objects = set()
    uac_events = {}
    for ev in events:
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        if ev.event_id != 5136:
            continue
        attr = (_directory_attribute_name(ev) or "").strip().lower()
        object_dn = _directory_object_dn(ev)
        object_dn_key = object_dn.lower()
        target = _extract_cn_from_dn(object_dn) or ev.target_domain_user or ev.target_user or object_dn
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        if attr in DELEGATION_ATTRIBUTES:
            delegation_change = DELEGATION_ATTRIBUTES[attr]
            direct_attr_objects.add((ev.computer or "", object_dn_key))
            key = (ev.computer or "", object_dn_key, attr, delegation_change)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(Alert(
                rule_name="Delegation Configuration Changed",
                severity="critical" if "resource-based" in delegation_change else "high",
                mitre_tactic="Persistence",
                mitre_technique="T1098",
                description=f"Delegation settings changed for {target or 'unknown object'} on {ev.computer}: {delegation_change}",
                explanation="Delegation changes can let an attacker impersonate users to services or establish resource-based constrained delegation for later abuse.",
                confidence="high",
                investigate_next="Confirm the delegation change through AD administration records, revert unauthorized delegation, and inspect the affected service or computer account.",
                event=ev,
                user=target,
                subject_user=actor,
                evidence={
                    "object_dn": object_dn,
                    "attribute": attr,
                    "delegation_change": delegation_change,
                    "evidence_strength": "high",
                },
            ))
            continue

        if attr != "useraccountcontrol":
            continue

        old_val = _safe_int(_first_present(ev.event_data, "OldValue", "PreviousValue"))
        new_val = _safe_int(_first_present(ev.event_data, "Value", "NewValue"))
        added_flags = _delegation_flags_added(old_val, new_val)
        if added_flags:
            delegation_change = ", ".join(added_flags)
            key = (ev.computer or "", object_dn_key, attr, delegation_change)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(Alert(
                rule_name="Delegation Configuration Changed",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1098",
                description=f"Delegation settings changed for {target or 'unknown object'} on {ev.computer}: {delegation_change}",
                explanation="Delegation changes can let an attacker impersonate users to services or establish resource-based constrained delegation for later abuse.",
                confidence="high",
                investigate_next="Confirm the delegation change through AD administration records, revert unauthorized delegation, and inspect the affected service or computer account.",
                event=ev,
                user=target,
                subject_user=actor,
                evidence={
                    "object_dn": object_dn,
                    "attribute": attr,
                    "delegation_change": delegation_change,
                    "old_uac_value": old_val,
                    "new_uac_value": new_val,
                    "evidence_strength": "high",
                },
            ))
            continue

        cluster_key = (ev.computer or "", object_dn_key, actor.lower())
        uac_events.setdefault(cluster_key, []).append(ev)

    for (host, object_dn_key, actor_key), cluster in uac_events.items():
        if (host, object_dn_key) in direct_attr_objects:
            continue
        values = []
        target = ""
        actor = ""
        for ev in cluster:
            target = target or (_extract_cn_from_dn(_directory_object_dn(ev)) or ev.target_domain_user or ev.target_user or _directory_object_dn(ev))
            actor = actor or ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
            value = _safe_int(_first_present(ev.event_data, "AttributeValue", "Value", "NewValue", "OldValue", "PreviousValue"))
            if value is not None:
                values.append(value)
        if len(values) < 2:
            continue
        old_val = min(values)
        new_val = max(values)
        added_flags = _delegation_flags_added(old_val, new_val)
        if not added_flags:
            continue
        delegation_change = ", ".join(added_flags)
        key = (host, object_dn_key, "useraccountcontrol_cluster", delegation_change)
        if key in seen:
            continue
        seen.add(key)
        primary_event = max(
            cluster,
            key=lambda item: _safe_int(_first_present(item.event_data, "AttributeValue", "Value", "NewValue")) or -1,
        )
        alerts.append(Alert(
            rule_name="Delegation Configuration Changed",
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"Delegation settings changed for {target or 'unknown object'} on {host}: {delegation_change}",
            explanation="Delegation changes can let an attacker impersonate users to services or establish resource-based constrained delegation for later abuse.",
            confidence="high",
            investigate_next="Confirm the delegation change through AD administration records, revert unauthorized delegation, and inspect the affected service or computer account.",
            event=primary_event,
            user=target,
            subject_user=actor or actor_key,
            evidence={
                "object_dn": _directory_object_dn(primary_event),
                "attribute": "useraccountcontrol",
                "delegation_change": delegation_change,
                "old_uac_value": old_val,
                "new_uac_value": new_val,
                "cluster_event_count": len(cluster),
                "evidence_strength": "high",
            },
        ))
    return alerts


def _group_policy_object_modified(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id == 4739:
            if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
                continue
            domain_name = (_first_present(ev.event_data, "DomainName") or "").strip().lower()
            host = (ev.computer or "").strip().lower()
            actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
            actor_simple = _normalize_identity(actor)
            if not domain_name or domain_name in {host, host.split(".", 1)[0]}:
                continue
            if actor_simple.endswith("$"):
                continue
            actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
            key = (ev.computer or "", actor.lower(), ev.event_id)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(Alert(
                rule_name="Domain Policy Changed",
                severity="high",
                mitre_tactic="Persistence",
                mitre_technique="T1484.001",
                description=f"Domain policy was changed on {ev.computer} by {actor}",
                explanation="Changes to domain policy can weaken security controls or establish broad persistence across many systems.",
                confidence="high",
                investigate_next="Review which policy settings changed, compare against approved change windows, and determine the scope of affected systems.",
                event=ev,
                subject_user=actor,
                evidence={"evidence_strength": "high"},
            ))
            continue
        if ev.event_id != 5136:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        object_dn = _directory_object_dn(ev)
        if DIRECTORY_POLICY_DN_MARKER not in (object_dn or "").lower():
            continue
        attr = (_directory_attribute_name(ev) or "").strip().lower()
        if attr not in GPO_SUSPICIOUS_ATTRIBUTES:
            continue
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        policy_name = _extract_cn_from_dn(object_dn) or object_dn
        key = (ev.computer or "", object_dn.lower(), attr)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name="Group Policy Object Modified",
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1484.001",
            description=f"GPO {policy_name or 'unknown'} was modified on {ev.computer} ({attr})",
            explanation="GPO modifications can distribute persistence, weaken security settings, or broadly change execution policy across many systems.",
            confidence="medium",
            investigate_next="Review the changed GPO revision, identify the linked OUs, and validate the modification against approved administration.",
            event=ev,
            subject_user=actor,
            evidence={
                "object_dn": object_dn,
                "attribute": attr,
                "policy_name": policy_name,
                "evidence_strength": "medium",
            },
        ))
    return alerts


def _scheduled_task_system_elevation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    process_events = sorted(
        (item for item in events if item.timestamp and item.event_id in (1, 4688)),
        key=lambda item: item.timestamp,
    )
    seen = set()

    def _task_name(command: str) -> str:
        match = re.search(r"/tn\s+\"?([^\"/]+?)\"?(?:\s|$)", command or "", re.IGNORECASE)
        return (match.group(1) or "").strip() if match else ""

    def _xml_path(command: str) -> str:
        match = re.search(r"/xml\s+\"?([^\"\s]+)\"?", command or "", re.IGNORECASE)
        return (match.group(1) or "").strip() if match else ""

    create_events = [
        item
        for item in process_events
        if _basename(item.process_name) == "schtasks.exe" and "/create" in (item.command_line or "").lower()
    ]

    for create in create_events:
        create_cmd = create.command_line or ""
        task_name = _task_name(create_cmd)
        if not task_name:
            continue

        host = create.computer or "unknown"
        actor = create.domain_user or create.subject_domain_user or create.event_data.get("User", "") or "unknown"
        run_event = next(
            (
                item
                for item in process_events
                if (item.computer or "unknown") == host
                and 0 <= (item.timestamp - create.timestamp).total_seconds() <= 900
                and _basename(item.process_name) == "schtasks.exe"
                and "/run" in (item.command_line or "").lower()
                and _task_name(item.command_line or "") == task_name
            ),
            None,
        )
        if not run_event:
            continue

        system_children = [
            item
            for item in process_events
            if (item.computer or "unknown") == host
            and 0 <= (item.timestamp - run_event.timestamp).total_seconds() <= 180
            and _basename(item.parent_process) in {"taskeng.exe", "taskhostw.exe", "taskhost.exe"}
            and "system" in (item.domain_user or item.subject_domain_user or item.event_data.get("User", "") or "").lower()
        ]
        if not system_children:
            continue

        delete_event = next(
            (
                item
                for item in process_events
                if (item.computer or "unknown") == host
                and 0 <= (item.timestamp - run_event.timestamp).total_seconds() <= 900
                and _basename(item.process_name) == "schtasks.exe"
                and "/delete" in (item.command_line or "").lower()
                and _task_name(item.command_line or "") == task_name
            ),
            None,
        )

        key = (host, actor.lower(), task_name.lower(), system_children[0].process_name.lower())
        if key in seen:
            continue
        seen.add(key)

        xml_path = _xml_path(create_cmd)
        alerts.append(
            Alert(
                rule_name="Scheduled Task SYSTEM Elevation",
                severity="critical",
                mitre_tactic="Privilege Escalation",
                mitre_technique="T1053.005",
                description=f"{actor} created and ran task '{task_name}' which spawned { _basename(system_children[0].process_name) } as SYSTEM on {host}",
                explanation=(
                    "Creating a scheduled task from attacker-controlled XML, running it immediately, and spawning a SYSTEM process from taskeng.exe "
                    "is a strong sign of scheduled-task-based privilege escalation."
                ),
                confidence="high",
                investigate_next="Recover the task XML, inspect the spawned SYSTEM command, and determine whether the task was removed to hide elevation activity.",
                event=system_children[0],
                user=actor,
                subject_user=actor,
                target_user=system_children[0].event_data.get("User", "") or system_children[0].domain_user or "NT AUTHORITY\\SYSTEM",
                process=system_children[0].process_name,
                parent_process=system_children[0].parent_process,
                scheduled_task=task_name,
                evidence={
                    "task_name": task_name,
                    "xml_path": xml_path,
                    "create_command": create_cmd[:400],
                    "run_command": (run_event.command_line or "")[:300],
                    "delete_command": (delete_event.command_line or "")[:300] if delete_event else "",
                    "system_processes": [item.process_name for item in system_children if item.process_name],
                    "system_commands": [(item.command_line or "")[:300] for item in system_children if item.command_line],
                    "evidence_strength": "high",
                },
            )
        )

    return alerts


def _process_hidden_account_provisioning(events: List[NormalizedEvent]) -> List[Alert]:
    alerts: List[Alert] = []
    process_events = sorted(
        (item for item in events if item.timestamp and item.event_id in (1, 4688)),
        key=lambda item: item.timestamp,
    )

    native_fake_accounts: Set[Tuple[str, str]] = set()
    native_hidden_users: Set[Tuple[str, str]] = set()
    for ev in events:
        host = ev.computer or "unknown"
        if ev.event_id == 4720:
            sam_account = (ev.event_data.get("SamAccountName", "") or ev.target_user or "").strip()
            if sam_account.endswith("$"):
                native_fake_accounts.add((host, _normalize_identity(sam_account)))
            continue
        if not _is_sysmon_registry_event(ev) or ev.event_id != 13:
            continue
        if (ev.event_data.get("EventType", "") or "").strip().lower() != "setvalue":
            continue
        target = _registry_target(ev)
        lowered = target.lower()
        if not lowered.startswith(SPECIAL_ACCOUNTS_USERLIST_PREFIX):
            continue
        username = target[len(SPECIAL_ACCOUNTS_USERLIST_PREFIX) :].split("\\", 1)[0].strip()
        details = (ev.event_data.get("Details", "") or ev.event_data.get("NewValue", "") or "").strip().lower()
        if not username:
            continue
        if details in {"0", "dword (0x00000000)", "0x00000000"} or "0x00000000" in details:
            native_hidden_users.add((host, _normalize_identity(username)))

    fake_clusters: Dict[Tuple[str, str], List[Dict[str, object]]] = {}
    hidden_clusters: Dict[Tuple[str, str], List[Dict[str, object]]] = {}

    def _cluster_for(
        clusters: Dict[Tuple[str, str], List[Dict[str, object]]],
        key: Tuple[str, str],
        event: NormalizedEvent,
    ) -> Dict[str, object]:
        entries = clusters.setdefault(key, [])
        if entries and event.timestamp and entries[-1]["last_seen"] and event.timestamp - entries[-1]["last_seen"] <= timedelta(minutes=5):
            cluster = entries[-1]
        else:
            cluster = {
                "events": [],
                "commands": [],
                "actors": set(),
                "processes": set(),
                "parent_processes": set(),
                "last_seen": event.timestamp,
            }
            entries.append(cluster)
        cluster["events"].append(event)
        command = (event.command_line or "").strip()
        if command and command not in cluster["commands"]:
            cluster["commands"].append(command)
        actor = (_extract_process_user(event) or "").strip()
        if actor:
            cluster["actors"].add(actor)
        process = (event.process_name or "").strip()
        if process:
            cluster["processes"].add(process)
        parent_process = (event.parent_process or "").strip()
        if parent_process:
            cluster["parent_processes"].add(parent_process)
        cluster["last_seen"] = event.timestamp
        return cluster

    for ev in process_events:
        command = (ev.command_line or "").strip()
        if not command:
            continue

        host = ev.computer or "unknown"
        fake_match = NET_USER_ADD_RE.search(command)
        if fake_match:
            username = (fake_match.group(1) or fake_match.group(2) or "").strip().strip('"')
            if username.endswith("$") and (host, _normalize_identity(username)) not in native_fake_accounts:
                _cluster_for(fake_clusters, (host, _normalize_identity(username)), ev)

        hidden_match = USERLIST_CMD_RE.search(command)
        if hidden_match:
            username = (hidden_match.group(2) or "").strip().strip('"')
            if username and (host, _normalize_identity(username)) not in native_hidden_users:
                _cluster_for(hidden_clusters, (host, _normalize_identity(username)), ev)

    for (host, _), clusters in fake_clusters.items():
        for cluster in clusters:
            cluster_events = cluster["events"]
            if not cluster_events:
                continue
            first_event = cluster_events[0]
            command_usernames = []
            for item in cluster["commands"]:
                match = NET_USER_ADD_RE.search(item)
                if not match:
                    continue
                parsed = (match.group(1) or match.group(2) or "").strip().strip('"')
                if parsed and parsed not in command_usernames:
                    command_usernames.append(parsed)
            username = command_usernames[0] if command_usernames else "unknown"
            actor_list = sorted(cluster["actors"])
            process_list = sorted(cluster["processes"])
            parent_list = sorted(cluster["parent_processes"])
            alerts.append(
                Alert(
                    rule_name="Fake Computer Account Created",
                    severity="high",
                    mitre_tactic="Persistence",
                    mitre_technique="T1136.001",
                    description=f"Computer-like account '{username}' created on {host}",
                    explanation="Explicit net user /add command execution created a local account ending in '$', which mimics machine-account naming and is commonly used to hide persistence. Related cmd/net/net1 command fan-out is collapsed into one activity.",
                    confidence="high",
                    investigate_next=f"Verify whether '{username}' should exist on {host}, inspect who launched the command, and review whether the account was later hidden or granted privileges.",
                    event=first_event,
                    user=username,
                    subject_user=actor_list[0] if len(actor_list) == 1 else first_event.event_data.get('User', '') or "unknown",
                    target_user=username,
                    process=first_event.process_name,
                    parent_process=first_event.parent_process,
                    evidence={
                        "new_account": username,
                        "created_by": actor_list[0] if len(actor_list) == 1 else actor_list,
                        "command_lines": cluster["commands"],
                        "processes": process_list,
                        "parent_processes": parent_list,
                        "collapsed_event_count": len(cluster_events),
                        "timestamps": [item.timestamp.isoformat() if item.timestamp else None for item in cluster_events],
                        "detection_source": "process_command",
                        "evidence_strength": "high",
                    },
                )
            )

    for (host, _), clusters in hidden_clusters.items():
        for cluster in clusters:
            cluster_events = cluster["events"]
            if not cluster_events:
                continue
            first_event = cluster_events[0]
            parsed_usernames = []
            registry_paths = []
            for item in cluster["commands"]:
                match = USERLIST_CMD_RE.search(item)
                if not match:
                    continue
                registry_root = match.group(1) or ""
                username = (match.group(2) or "").strip().strip('"')
                if username and username not in parsed_usernames:
                    parsed_usernames.append(username)
                if registry_root and username:
                    registry_paths.append(f"{registry_root}\\{username}")
            username = parsed_usernames[0] if parsed_usernames else "unknown"
            actor_list = sorted(cluster["actors"])
            process_list = sorted(cluster["processes"])
            parent_list = sorted(cluster["parent_processes"])
            alerts.append(
                Alert(
                    rule_name="Hidden User Registry Value",
                    severity="high",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1564.002",
                    description=f"Winlogon UserList hid account {username or 'unknown'} on {host}",
                    explanation="Explicit reg add execution set SpecialAccounts\\UserList to 0, which hides the account from common logon and user-listing interfaces. Related cmd/reg fan-out is collapsed into one activity.",
                    confidence="high",
                    investigate_next="Confirm the account exists locally, inspect how it was created, and review whether it was used for remote access or added to privileged groups.",
                    event=first_event,
                    user=username,
                    subject_user=actor_list[0] if len(actor_list) == 1 else first_event.event_data.get('User', '') or "unknown",
                    target_user=username,
                    process=first_event.process_name,
                    parent_process=first_event.parent_process,
                    registry_key=registry_paths[0] if registry_paths else "",
                    evidence={
                        "hidden_username": username,
                        "registry_key": registry_paths[0] if registry_paths else "",
                        "registry_paths": registry_paths,
                        "command_lines": cluster["commands"],
                        "processes": process_list,
                        "parent_processes": parent_list,
                        "modified_by": actor_list[0] if len(actor_list) == 1 else actor_list,
                        "collapsed_event_count": len(cluster_events),
                        "timestamps": [item.timestamp.isoformat() if item.timestamp else None for item in cluster_events],
                        "detection_source": "process_command",
                        "evidence_strength": "high",
                    },
                )
            )

    return alerts


def _extract_wmi_entity_name(value: str) -> str:
    match = re.search(r'Name\s*=\s*"([^"]+)"', value or "", re.IGNORECASE)
    if match:
        return (match.group(1) or "").strip()
    return (value or "").strip().strip('"')


def _sysmon_wmi_permanent_subscription(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp)
    consumed: Set[Tuple[str, str, str]] = set()

    for ev in timed_events:
        if ev.event_id not in WMI_PERSISTENCE_EVENT_TYPES:
            continue
        if not _is_sysmon_event(ev):
            continue

        operation = _first_present(ev.event_data, "Operation").lower()
        if not any(token in operation for token in ("created", "modified")):
            continue

        host = ev.computer or "unknown"
        actor = (_first_present(ev.event_data, "User") or ev.domain_user or "unknown").strip()
        cluster = [
            other
            for other in timed_events
            if other.event_id in WMI_PERSISTENCE_EVENT_TYPES
            and _is_sysmon_event(other)
            and (other.computer or "unknown") == host
            and ((_first_present(other.event_data, "User") or other.domain_user or "unknown").strip() == actor)
            and any(token in _first_present(other.event_data, "Operation").lower() for token in ("created", "modified"))
            and abs((other.timestamp - ev.timestamp).total_seconds()) <= 900
        ]
        if not cluster:
            continue

        consumer_events = [item for item in cluster if item.event_id == 20]
        filter_events = [item for item in cluster if item.event_id == 19]
        binding_events = [item for item in cluster if item.event_id == 21]

        consumer_names = sorted(
            {
                _extract_wmi_entity_name(_first_present(item.event_data, "Consumer", "Name"))
                for item in consumer_events + binding_events
                if _extract_wmi_entity_name(_first_present(item.event_data, "Consumer", "Name"))
            }
        )
        filter_names = sorted(
            {
                _extract_wmi_entity_name(_first_present(item.event_data, "Filter", "Name"))
                for item in filter_events + binding_events
                if _extract_wmi_entity_name(_first_present(item.event_data, "Filter", "Name"))
            }
        )
        queries = sorted(
            {
                _first_present(item.event_data, "Query", "QueryText").strip()
                for item in filter_events
                if _first_present(item.event_data, "Query", "QueryText").strip()
            }
        )
        destinations = sorted(
            {
                _first_present(item.event_data, "Destination", "CommandLineTemplate", "ExecutablePath").strip()
                for item in consumer_events
                if _first_present(item.event_data, "Destination", "CommandLineTemplate", "ExecutablePath").strip()
            }
        )
        consumer_types = sorted(
            {
                _first_present(item.event_data, "Type").strip()
                for item in consumer_events
                if _first_present(item.event_data, "Type").strip()
            }
        )

        near_processes = []
        for other in timed_events:
            if other.event_id not in (1, 4688):
                continue
            if (other.computer or "unknown") != host:
                continue
            if abs((other.timestamp - ev.timestamp).total_seconds()) > 900:
                continue
            cmd = (other.command_line or "").lower()
            proc = _basename(other.process_name)
            if proc in {"wmic.exe", "scrcons.exe", "wmighost.exe"} or "\\root\\subscription" in cmd:
                entry = {
                    "process": other.process_name or proc,
                    "command_line": (other.command_line or "")[:400],
                }
                if entry not in near_processes:
                    near_processes.append(entry)

        has_binding = bool(binding_events)
        has_consumer = bool(consumer_events)
        has_filter = bool(filter_events)
        has_executable_consumer = any(
            marker in " ".join(destinations).lower()
            for marker in ("cmd.exe", "powershell", "wscript", "cscript", "mshta", "rundll32")
        )
        has_script_consumer = any("script" in item.lower() for item in consumer_types) or any(
            marker in " ".join(destinations).lower()
            for marker in ("activexobject", "execquery", "xmlhttp", "adodb.stream")
        )
        if not (has_binding or has_consumer or has_filter):
            continue

        fingerprint = (
            host.lower(),
            actor.lower(),
            tuple(filter_names),
            tuple(consumer_names),
            tuple(destinations),
        )
        if fingerprint in consumed:
            continue
        consumed.add(fingerprint)

        first = min(cluster, key=lambda item: item.timestamp)
        severity = "critical" if has_binding and (has_executable_consumer or has_script_consumer) else "high"
        confidence = "high" if has_binding or has_executable_consumer or has_script_consumer else "medium"
        summary_targets = consumer_names or filter_names or ["unknown WMI object"]
        alerts.append(
            Alert(
                rule_name="WMI Permanent Event Subscription",
                severity=severity,
                mitre_tactic="Persistence",
                mitre_technique="T1546.003",
                description=f"{actor} created a WMI permanent event subscription on {host} targeting {', '.join(summary_targets[:2])}",
                explanation=(
                    "Sysmon WmiFilterEvent, WmiConsumerEvent, and WmiBindingEvent records show a permanent WMI event subscription. "
                    "CommandLine and ActiveScript consumers are especially strong evidence of attacker persistence."
                ),
                confidence=confidence,
                investigate_next=(
                    "Review the WMI filter query, consumer type, and destination script or command, then remove the filter/consumer/binding if unauthorized."
                ),
                event=first,
                user=actor,
                process=near_processes[0]["process"] if near_processes else "",
                evidence={
                    "actor_user": actor,
                    "filter_names": filter_names,
                    "consumer_names": consumer_names,
                    "queries": queries[:10],
                    "destinations": destinations[:10],
                    "consumer_types": consumer_types,
                    "creator_processes": near_processes[:10],
                    "command_line": near_processes[0]["command_line"] if near_processes else "",
                    "binding_present": has_binding,
                    "script_consumer": has_script_consumer,
                    "executable_consumer": has_executable_consumer,
                    "collapsed_event_count": len(cluster),
                    "timestamps": [item.timestamp.isoformat() if item.timestamp else None for item in cluster],
                    "evidence_strength": "high" if confidence == "high" else "medium",
                },
            )
        )

    return alerts


def _extract_owner_sid(value: str) -> str:
    match = re.search(r"O:(S-\d-(?:\d+-)+\d+)", value or "", re.IGNORECASE)
    return (match.group(1) or "").strip() if match else ""


def _extract_acl_sids(value: str) -> List[str]:
    return sorted({sid for sid in re.findall(r"S-\d-(?:\d+-)+\d+", value or "", re.IGNORECASE) if sid})


def _extract_ocsp_principals(value: str) -> List[str]:
    principals = []
    for match in re.findall(r"Allow\([^)]+\)\t([^\r\n]+)", value or "", re.IGNORECASE):
        principal = (match or "").strip()
        if principal and principal not in principals:
            principals.append(principal)
    return principals


def _adminsdholder_permissions_changed(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 5136:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        object_dn = _directory_object_dn(ev)
        attr = (_directory_attribute_name(ev) or "").strip().lower()
        if ADMINSDHOLDER_DN_MARKER not in (object_dn or "").lower() or attr != "ntsecuritydescriptor":
            continue
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        key = (ev.computer or "", object_dn.lower(), actor.lower())
        if key in seen:
            continue
        seen.add(key)
        acl_value = _first_present(ev.event_data, "AttributeValue")
        alerts.append(Alert(
            rule_name="AdminSDHolder Permissions Changed",
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"AdminSDHolder permissions were modified on {ev.computer} by {actor}",
            explanation="AdminSDHolder ACL changes can backdoor privileged object permissions and survive SDProp propagation across protected accounts.",
            confidence="high",
            investigate_next="Review the new AdminSDHolder ACL, identify added principals or rights, and revert any unauthorized entries before SDProp propagates them.",
            event=ev,
            subject_user=actor,
            evidence={
                "object_dn": object_dn,
                "attribute": attr,
                "acl_sids": _extract_acl_sids(acl_value)[:12],
                "operation_type": _first_present(ev.event_data, "OperationType", "OpCorrelationID"),
                "evidence_strength": "high",
            },
        ))
    return alerts


def _adminsdholder_rights_obfuscation(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 5136:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        object_dn = _directory_object_dn(ev)
        attr = (_directory_attribute_name(ev) or "").strip().lower()
        object_class = _first_present(ev.event_data, "ObjectClass").lower()
        if EXTENDED_RIGHTS_DN_MARKER not in (object_dn or "").lower():
            continue
        if attr != "localizationdisplayid" or object_class != "controlaccessright":
            continue
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        key = (ev.computer or "", object_dn.lower(), actor.lower(), _first_present(ev.event_data, "AttributeValue"))
        if key in seen:
            continue
        seen.add(key)
        right_name = _extract_cn_from_dn(object_dn) or object_dn
        alerts.append(Alert(
            rule_name="AdminSDHolder Rights Obfuscation",
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"Extended-right metadata for {right_name} was altered on {ev.computer}",
            explanation="Changing localizationDisplayId on protected extended rights can help hide AdminSDHolder backdoors or confuse downstream auditing and review.",
            confidence="medium",
            investigate_next="Inspect the associated extended right, compare the original display metadata, and review whether it was changed to conceal a privilege backdoor.",
            event=ev,
            subject_user=actor,
            evidence={
                "object_dn": object_dn,
                "attribute": attr,
                "new_value": _first_present(ev.event_data, "AttributeValue"),
                "evidence_strength": "medium",
            },
        ))
    return alerts


def _suspicious_spn_assignment(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        object_dn = ""
        object_class = ""
        spn_value = ""
        target = ""
        detection_source = "directory_change"

        if ev.event_id == 5136:
            attr = (_directory_attribute_name(ev) or "").strip().lower()
            if attr != "serviceprincipalname":
                continue
            object_dn = _directory_object_dn(ev)
            object_class = _first_present(ev.event_data, "ObjectClass").lower()
            spn_value = _first_present(ev.event_data, "AttributeValue").strip()
            target = _extract_cn_from_dn(object_dn) or object_dn
        elif ev.event_id == 4688 and _basename(ev.process_name) == "setspn.exe":
            parsed = _parse_setspn_add_command(ev.command_line or _first_present(ev.event_data, "CommandLine"))
            if not parsed:
                continue
            spn_value, target = parsed
            object_class = "computer" if target.endswith("$") else "user"
            detection_source = "process_command"
        else:
            continue

        if not spn_value or not target:
            continue

        spn_lower = spn_value.lower()

        if object_class == "user":
            if "/" not in spn_value or not spn_lower.startswith(SPN_SUSPICIOUS_PREFIXES):
                continue
            rule_name = "SPN Added to User Account"
            severity = "high"
        elif object_class == "computer":
            if spn_lower.startswith(DEFAULT_COMPUTER_SPN_PREFIXES):
                continue
            rule_name = "SPN Added to Computer Account"
            if "/" not in spn_value:
                continue
            severity = "high" if spn_lower.startswith(SPN_SUSPICIOUS_PREFIXES) else "medium"
        else:
            continue

        object_key = object_dn.lower() if object_dn else _normalized_account_key(target)
        key = (rule_name, ev.computer or "", object_key, spn_lower, actor.lower(), detection_source)
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name=rule_name,
            severity=severity,
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor} assigned SPN {spn_value} to {target} on {ev.computer}",
            explanation="Service principal name changes can enable Kerberos abuse, delegation abuse, or stealth service impersonation on user and computer accounts.",
            confidence=(
                "high"
                if object_class == "user" or (object_class == "computer" and severity == "high")
                else "medium"
            ),
            investigate_next="Validate whether the SPN is expected for the account, review who changed it, and inspect follow-on Kerberos ticket activity for the modified principal.",
            event=ev,
            user=target,
            subject_user=actor,
            evidence={
                "object_dn": object_dn,
                "object_class": object_class,
                "spn_value": spn_value,
                "detection_source": detection_source,
                "command_line": ev.command_line,
                "evidence_strength": (
                    "high"
                    if object_class == "user" or (object_class == "computer" and severity == "high")
                    else "medium"
                ),
            },
        ))
    return alerts


def _ad_object_owner_changed(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)
    seen = set()
    for ev in timed_events:
        if ev.event_id != 5136:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        attr = (_directory_attribute_name(ev) or "").strip().lower()
        if attr != "ntsecuritydescriptor":
            continue
        object_dn = _directory_object_dn(ev)
        if ADMINSDHOLDER_DN_MARKER in (object_dn or "").lower():
            continue
        owner_sid = _extract_owner_sid(_first_present(ev.event_data, "AttributeValue"))
        if not owner_sid:
            continue
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        logon_id = _first_present(ev.event_data, "SubjectLogonId", "LogonId")
        write_owner = None
        for other in timed_events:
            if other.timestamp < ev.timestamp - timedelta(minutes=5) or other.timestamp > ev.timestamp + timedelta(minutes=5):
                continue
            if (other.computer or "") != (ev.computer or "") or other.event_id != 4662:
                continue
            if logon_id and _first_present(other.event_data, "SubjectLogonId", "LogonId") != logon_id:
                continue
            access_mask = (_first_present(other.event_data, "AccessMask") or "").lower()
            access_list = (_first_present(other.event_data, "AccessList") or "").lower()
            if access_mask == "0x00080000" or "1540" in access_list:
                write_owner = other
                break
        if not write_owner:
            continue
        key = (ev.computer or "", object_dn.lower(), owner_sid, actor.lower())
        if key in seen:
            continue
        seen.add(key)
        target = _extract_cn_from_dn(object_dn) or object_dn
        alerts.append(Alert(
            rule_name="AD Object Owner Changed",
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor} changed the owner of {target} on {ev.computer}",
            explanation="Changing an AD object's owner enables follow-on ACL takeover and can establish durable control over the target object.",
            confidence="high",
            investigate_next="Review the new owner SID, inspect subsequent ACL changes on the object, and revert unauthorized ownership changes immediately.",
            event=ev,
            user=target,
            subject_user=actor,
            evidence={
                "object_dn": object_dn,
                "new_owner_sid": owner_sid,
                "write_owner_access": True,
                "evidence_strength": "high",
            },
        ))
    return alerts


def _adcs_ocsp_configuration_tampering(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    grouped: Dict[Tuple[str, str, str], List[NormalizedEvent]] = {}
    for ev in sorted((item for item in events if item.timestamp), key=lambda item: item.timestamp):
        if ev.event_id not in (5123, 5124, 4876, 4877, 4885):
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        actor = ev.subject_domain_user or ev.domain_user or ev.subject_user or "unknown"
        logon_id = _first_present(ev.event_data, "SubjectLogonId", "LogonId")
        grouped.setdefault((ev.computer or "", actor.lower(), logon_id), []).append(ev)

    for (host, actor_key, logon_id), cluster in grouped.items():
        if len(cluster) < 2:
            continue
        actor = cluster[0].subject_domain_user or cluster[0].domain_user or cluster[0].subject_user or "unknown"
        audit_disabled = any(
            ev.event_id == 5123
            and (_first_present(ev.event_data, "PropertyName") or "").lower() == "auditfilter"
            and (_first_present(ev.event_data, "NewValue") or "").strip() == "0"
            for ev in cluster
        )
        backup_or_restore = any(ev.event_id in (4876, 4877) for ev in cluster)
        security_changes = [ev for ev in cluster if ev.event_id == 5124]
        unusual_principals = sorted(
            {
                principal
                for ev in security_changes
                for principal in _extract_ocsp_principals(_first_present(ev.event_data, "NewSecuritySettings"))
                if principal.lower() not in ADCS_OCSP_ALLOWED_PRINCIPALS
            }
        )
        if not ((audit_disabled and (backup_or_restore or unusual_principals)) or (backup_or_restore and unusual_principals)):
            continue

        first = cluster[0]
        alerts.append(Alert(
            rule_name="AD CS OCSP Configuration Tampering",
            severity="critical" if audit_disabled and unusual_principals else "high",
            mitre_tactic="Defense Evasion",
            mitre_technique="T1562.001",
            description=f"AD CS OCSP configuration was modified on {host} by {actor}",
            explanation="Combined OCSP security-setting changes, audit-filter tampering, and backup/restore activity can hide or enable unauthorized AD CS responder access.",
            confidence="high" if audit_disabled else "medium",
            investigate_next="Review the OCSP responder ACLs, revert unauthorized principals or audit changes, and inspect certificate-service admin activity from the same session.",
            event=first,
            subject_user=actor,
            evidence={
                "subject_logon_id": logon_id,
                "audit_filter_disabled": audit_disabled,
                "backup_or_restore": backup_or_restore,
                "unusual_principals": unusual_principals,
                "event_ids": [ev.event_id for ev in cluster],
                "evidence_strength": "high" if audit_disabled else "medium",
            },
        ))
    return alerts


def _remote_samr_password_reset(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    timed_events = sorted((ev for ev in events if ev.timestamp), key=lambda ev: ev.timestamp)
    seen = set()

    for ev in timed_events:
        if ev.event_id != 4724:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue

        actor = ev.subject_domain_user or ev.subject_user or ""
        target = ev.target_domain_user or ev.target_user or ""
        if not actor or not target:
            continue
        if _normalize_identity(actor) == _normalize_identity(target):
            continue
        if _normalize_identity(actor).endswith("$"):
            continue

        logon_id = _first_present(ev.event_data, "SubjectLogonId", "LogonId")
        samr_event = None
        for other in timed_events:
            if other.timestamp < ev.timestamp - timedelta(minutes=10) or other.timestamp > ev.timestamp + timedelta(minutes=10):
                continue
            if (other.computer or "") != (ev.computer or ""):
                continue
            if other.event_id != 5145:
                continue
            if logon_id and _first_present(other.event_data, "SubjectLogonId", "LogonId") != logon_id:
                continue
            share_name = (_first_present(other.event_data, "ShareName") or "").lower()
            relative_target = (_first_present(other.event_data, "RelativeTargetName") or "").lower()
            if "ipc$" not in share_name or "samr" not in relative_target:
                continue
            samr_event = other
            break

        if not samr_event:
            continue

        source_ip = samr_event.source_ip or _first_present(samr_event.event_data, "IpAddress")
        if not source_ip or source_ip in {"-", "", "::1", "127.0.0.1"}:
            continue

        target_sid = _first_present(ev.event_data, "TargetSid")
        severity = "critical" if _is_privileged_reset_target(target, target_sid) else "high"
        evidence_strength = "high" if severity == "critical" else "medium"
        key = (ev.computer or "", _normalize_identity(actor), _normalize_identity(target), source_ip)
        if key in seen:
            continue
        seen.add(key)

        alerts.append(Alert(
            rule_name="Remote SAMR Password Reset",
            severity=severity,
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor} reset the password for {target} on {ev.computer} through remote SAMR access from {source_ip}",
            explanation="Password resets performed through IPC$/SAMR are consistent with remote account manipulation and can be used to seize or restore access.",
            confidence="high" if severity == "critical" else "medium",
            investigate_next="Validate the password reset with the account owner, review the remote admin source, and reset any accounts changed through unauthorized SAMR activity.",
            event=ev,
            user=target,
            subject_user=actor,
            source_ip=source_ip,
            evidence={
                "source_ip": source_ip,
                "share_name": _first_present(samr_event.event_data, "ShareName"),
                "relative_target_name": _first_present(samr_event.event_data, "RelativeTargetName"),
                "target_sid": target_sid,
                "subject_logon_id": logon_id,
                "evidence_strength": evidence_strength,
            },
        ))

    return alerts


def _privileged_account_password_reset(events: List[NormalizedEvent]) -> List[Alert]:
    alerts = []
    seen = set()
    for ev in events:
        if ev.event_id != 4724:
            continue
        if not ((ev.provider or "").lower().find("security") >= 0 or (ev.channel or "").lower() == "security"):
            continue
        actor = ev.subject_domain_user or ev.subject_user or ""
        target = ev.target_domain_user or ev.target_user or ""
        target_sid = _first_present(ev.event_data, "TargetSid")
        if not target or _normalize_identity(actor) == _normalize_identity(target):
            continue
        if _normalize_identity(actor).endswith("$"):
            continue
        if not _is_privileged_reset_target(target, target_sid):
            continue
        key = (ev.computer or "", _normalize_identity(target), _normalize_identity(actor))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert(
            rule_name="Privileged Account Password Reset",
            severity="critical",
            mitre_tactic="Persistence",
            mitre_technique="T1098",
            description=f"{actor or 'Unknown actor'} reset the password for {target} on {ev.computer}",
            explanation="Resetting a privileged account password can be used to seize or preserve administrative access.",
            confidence="high",
            investigate_next="Validate the reset with the account owner and identity team, review all follow-on logons, and rotate affected privileged credentials.",
            event=ev,
            user=target,
            subject_user=actor,
            evidence={
                "target_sid": target_sid,
                "evidence_strength": "high",
            },
        ))
    return alerts


def _first_present(values: Dict[str, str], *names: str) -> str:
    for name in names:
        value = (values.get(name, "") or "").strip()
        if value:
            return value
    return ""


def _check(
    ev: NormalizedEvent,
    grouped_account_event_ids: Set[int] | None = None,
    grouped_startup_event_ids: Set[int] | None = None,
) -> List[Alert]:
    alerts = []
    ed = ev.event_data
    grouped_account_event_ids = grouped_account_event_ids or set()
    grouped_startup_event_ids = grouped_startup_event_ids or set()

    if ev.event_id in (4688, 1):
        cmd = (ev.command_line or "").lower()
        proc = (ev.process_name or ed.get("Image", "")).replace("\\", "/").split("/")[-1].lower()
        parent = (ev.parent_process or ed.get("ParentImage", "")).replace("\\", "/").split("/")[-1].lower()
        if cmd:
            if proc == "bitsadmin.exe" and "/transfer" in cmd:
                remote_url = ""
                match = URL_RE.search(ev.command_line or "")
                if match:
                    remote_url = match.group(0)
                alerts.append(Alert(
                    rule_name="BITSAdmin Transfer", severity="high",
                    mitre_tactic="Persistence", mitre_technique="T1197",
                    description=f"BITSAdmin initiated a transfer on {ev.computer}: {remote_url or cmd[:180]}",
                    explanation="BITS jobs are frequently abused to download payloads or stage content under the guise of legitimate background transfers.",
                    confidence="high",
                    investigate_next="Inspect the BITS job name, downloaded file path, and follow-on execution, then verify whether the transfer was approved.",
                    event=ev,
                    evidence={
                        "command_line": (ev.command_line or "")[:600],
                        "remote_url": remote_url,
                        "evidence_strength": "high",
                    },
                ))

            if proc == "bitsadmin.exe" and "/setnotifycmdline" in cmd:
                alerts.append(Alert(
                    rule_name="BITS Notify Command Persistence", severity="critical",
                    mitre_tactic="Persistence", mitre_technique="T1197",
                    description=f"BITS job notify command configured on {ev.computer}: {cmd[:180]}",
                    explanation="BITS notify commands can launch attacker-controlled programs whenever a job completes, creating a stealthy persistence mechanism.",
                    confidence="high",
                    investigate_next="Recover the job configuration, inspect the notify command target, and determine whether the callback launched successfully.",
                    event=ev,
                    evidence={"command_line": (ev.command_line or "")[:600], "evidence_strength": "high"},
                ))

            if parent == "mobsync.exe" and proc in {"cmd.exe", "powershell.exe", "pwsh.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe"}:
                alerts.append(Alert(
                    rule_name="BITS Notify Command Execution", severity="critical",
                    mitre_tactic="Persistence", mitre_technique="T1197",
                    description=f"BITS notify callback launched {proc} on {ev.computer}",
                    explanation="Suspicious child processes spawned by mobsync.exe are consistent with a BITS job notify callback executing attacker-controlled content.",
                    confidence="high",
                    investigate_next="Inspect the BITS job that triggered the callback, recover the launched command, and determine whether additional payloads or persistence were installed.",
                    event=ev,
                    process=ev.process_name,
                    parent_process=ev.parent_process,
                    evidence={
                        "command_line": (ev.command_line or "")[:600],
                        "parent_process": ev.parent_process,
                        "evidence_strength": "high",
                    },
                ))

            if "schtasks" in cmd and "/create" in cmd:
                suspicious = any(marker in cmd for marker in ("powershell", "cmd.exe", "mshta", "rundll32", "regsvr32", " -enc", "encodedcommand", "\\\\"))
                if suspicious:
                    alerts.append(Alert(
                        rule_name="Suspicious Scheduled Task Command", severity="high",
                        mitre_tactic="Persistence", mitre_technique="T1053.005",
                        description=f"Suspicious schtasks creation command on {ev.computer}: {cmd[:180]}",
                        explanation="The command line creates a scheduled task that launches scripting interpreters, encoded content, or remote paths commonly used for malicious persistence or remote execution.",
                        confidence="high",
                        investigate_next="Extract the full scheduled task command, decode any payloads, and determine whether it targeted a local or remote host.",
                        event=ev,
                        evidence={"command_line": cmd[:600], "evidence_strength": "high"},
                    ))

            if re.search(r"\bsc(\.exe)?\b", cmd) and any(token in cmd for token in (" create ", " config ", " failure ")):
                if _matches_specific_service_command(ev.command_line or ""):
                    pass
                else:
                    suspicious = any(marker in cmd for marker in ("powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "\\\\", "\\users\\", "\\programdata\\", "\\temp\\"))
                    if suspicious:
                        alerts.append(Alert(
                            rule_name="Suspicious Service Configuration Command", severity="high",
                            mitre_tactic="Persistence", mitre_technique="T1543.003",
                            description=f"Suspicious service configuration command on {ev.computer}: {cmd[:180]}",
                            explanation="The command line modifies or creates a service using an interpreter, remote path, or user-controlled location associated with malicious service execution.",
                            confidence="high",
                            investigate_next="Review the resulting service configuration, confirm whether the target host was local or remote, and inspect the payload path or command that the service executes.",
                            event=ev,
                            evidence={"command_line": cmd[:600], "evidence_strength": "high"},
                        ))

    if ev.event_id in (4698, 4702):
        task = ed.get("TaskName", "")
        content = ed.get("TaskContent", "")
        user = ev.domain_user or "unknown"
        if task.lower().startswith("\\microsoft\\windows\\"):
            return alerts
        alerts.append(Alert(
            rule_name="Scheduled Task Created", severity="high",
            mitre_tactic="Persistence", mitre_technique="T1053.005",
            description=f"Task '{task}' created by {user} on {ev.computer}",
            explanation="Attackers create scheduled tasks to re-execute malware after reboot or at specific intervals.",
            confidence="medium",
            investigate_next=f"Examine the task content/action for '{task}'. Check if it runs a suspicious binary or script. Verify with change management.",
            event=ev, scheduled_task=task,
            evidence={"task_name": task, "content": content[:500], "user": user, "evidence_strength": "medium"},
        ))

        content_l = (content or "").lower()
        suspicious_markers = [marker for marker in SUSPICIOUS_TASK_MARKERS if marker in content_l]
        if "\\\\" in content and "admin$" in content_l:
            suspicious_markers.append("unc_admin_share")
        if suspicious_markers:
            alerts.append(Alert(
                rule_name="Suspicious Scheduled Task",
                severity="critical" if "encodedcommand" in content_l or "frombase64string" in content_l else "high",
                mitre_tactic="Persistence", mitre_technique="T1053.005",
                description=f"Task '{task}' contains suspicious execution content on {ev.computer}",
                explanation="The scheduled task content launches a scripting engine, encoded command, or remote/admin-share path consistent with attacker tradecraft.",
                confidence="high",
                investigate_next=f"Extract the full XML for '{task}', decode any embedded payloads, and confirm whether the task was created by approved administration.",
                event=ev,
                scheduled_task=task,
                evidence={
                    "task_name": task,
                    "content": content[:800],
                    "user": user,
                    "suspicious_markers": sorted(set(suspicious_markers)),
                    "evidence_strength": "high",
                },
            ))

    if ev.event_id in (7045, 4697):
        svc = ed.get("ServiceName", "")
        svc_file = ed.get("ImagePath", "") or ed.get("ServiceFileName", "")
        svc_acct = ed.get("ServiceAccount", "") or ed.get("AccountName", "")
        svc_l = svc.lower()
        svc_file_l = svc_file.lower()
        if svc_l in BENIGN_SERVICE_NAMES or any(marker in svc_file_l for marker in BENIGN_SERVICE_PATH_MARKERS):
            return alerts
        is_system = "system" in svc_acct.lower()
        alerts.append(Alert(
            rule_name="Service Installed", severity="critical" if is_system else "high",
            mitre_tactic="Persistence", mitre_technique="T1543.003",
            description=f"Service '{svc}' installed on {ev.computer} | Account: {svc_acct or 'unknown'} | Binary: {svc_file or 'unknown'}",
            explanation=f"Malicious services provide persistent code execution{' with SYSTEM privileges' if is_system else ''}. Verify the binary is legitimate and whether the service name/path matches approved software.",
            confidence="medium" if svc_file else "low",
            investigate_next=f"Hash the binary '{svc_file}' and check it on VirusTotal. Verify whether this service was installed by authorized change. Check if the service is still running.",
            event=ev, service=svc,
            evidence={
                "service_name": svc,
                "binary": svc_file,
                "account": svc_acct,
                "evidence_strength": "medium" if svc_file else "low",
            },
        ))

        svc_file_l = svc_file.lower()
        suspicious_markers = [marker for marker in SUSPICIOUS_SERVICE_EXECUTION_MARKERS if marker in svc_file_l]
        if svc_file.startswith("\\\\"):
            suspicious_markers.append("unc_path")
        if suspicious_markers:
            alerts.append(Alert(
                rule_name="Suspicious Service Execution",
                severity="critical",
                mitre_tactic="Persistence", mitre_technique="T1543.003",
                description=f"Service '{svc}' on {ev.computer} launches a suspicious command or path",
                explanation="The service binary path uses an interpreter, encoded command style, admin share, UNC path, or user-controlled location that is commonly used for payload execution.",
                confidence="high",
                investigate_next=f"Recover the command configured for service '{svc}', determine whether it was used for remote execution, and inspect the payload path '{svc_file}'.",
                event=ev,
                service=svc,
                evidence={
                    "service_name": svc,
                    "binary": svc_file,
                    "account": svc_acct,
                    "suspicious_markers": suspicious_markers,
                    "evidence_strength": "high",
                },
            ))

    if ev.event_id in (13, 4657):
        target = (ed.get("TargetObject", "") or ed.get("ObjectName", "")).lower()
        run_keys = ["\\currentversion\\run", "\\currentversion\\runonce"]
        for key in run_keys:
            if key in target:
                value = ed.get("Details", "") or ed.get("NewValue", "")
                alerts.append(Alert(
                    rule_name="Registry Run Key Persistence", severity="critical",
                    mitre_tactic="Persistence", mitre_technique="T1547.001",
                    description=f"Run key on {ev.computer}: {target} -> {value[:100]}",
                    explanation="Registry Run keys auto-execute programs at logon. This is one of the most common persistence mechanisms.",
                    confidence="high",
                    investigate_next=f"Check what binary the run key points to. Hash it and verify legitimacy. Check when the key was first created.",
                    event=ev, registry_key=target,
                    evidence={"key": target, "value": value[:300], "evidence_strength": "high"},
                ))
                break

        if "\\command processor\\autorun" in target:
            value = ed.get("Details", "") or ed.get("NewValue", "")
            if value:
                alerts.append(Alert(
                    rule_name="Command Processor AutoRun Persistence", severity="critical",
                    mitre_tactic="Persistence", mitre_technique="T1546",
                    description=f"Command Processor AutoRun modified on {ev.computer}: {value[:120]}",
                    explanation="Command Processor AutoRun executes commands whenever cmd.exe starts, making it a stealthy persistence mechanism.",
                    confidence="high",
                    investigate_next="Review the autorun command, determine who set it, and confirm whether cmd.exe startup behavior was intentionally modified.",
                    event=ev, registry_key=target,
                    evidence={"key": target, "value": value[:300], "evidence_strength": "high"},
                ))

    if ev.event_id in (19, 20, 21):
        provider_context = f"{ev.provider} {ev.channel}".lower()
        if "wmi" not in provider_context:
            return alerts

        wmi_type = {19: "Filter", 20: "Consumer", 21: "Binding"}.get(ev.event_id, "")
        name = ed.get("Name", "") or ed.get("Operation", "")
        query = ed.get("Query", "") or ed.get("QueryText", "")
        consumer = ed.get("Consumer", "") or ed.get("ConsumerName", "")
        command_template = ed.get("CommandLineTemplate", "") or ed.get("ExecutablePath", "")
        binding_filter = ed.get("Filter", "") or ed.get("FilterName", "")

        if ev.event_id == 19:
            strong = bool(query)
            weak = bool(name)
            summary = query or name
        elif ev.event_id == 20:
            strong = bool(command_template)
            weak = bool(name or consumer)
            summary = command_template or consumer or name
        else:
            strong = bool(binding_filter and consumer)
            weak = bool(binding_filter or consumer or name)
            summary = " -> ".join([v for v in (binding_filter, consumer, name) if v])

        if not strong and not weak:
            return alerts

        alerts.append(Alert(
            rule_name=f"WMI {wmi_type} Created", severity="high" if strong else "medium",
            mitre_tactic="Persistence", mitre_technique="T1546.003",
            description=f"WMI {wmi_type} on {ev.computer}: {summary or 'unknown'}",
            explanation="WMI subscriptions provide fileless persistence. All three components (Filter, Consumer, Binding) together form an active trigger.",
            confidence="high" if strong else "low",
            investigate_next="Check for all three WMI components (Filter/Consumer/Binding). Examine what the Consumer executes.",
            event=ev,
            evidence={
                "wmi_type": wmi_type,
                "name": name,
                "query": query,
                "consumer": consumer,
                "command_template": command_template,
                "binding_filter": binding_filter,
                "evidence_strength": "high" if strong else "low",
            },
        ))

    if ev.event_id == 11:
        target = (ed.get("TargetFilename", "") or "").lower()
        exts = (".exe", ".bat", ".cmd", ".vbs", ".ps1", ".lnk")
        if id(ev) in grouped_startup_event_ids:
            return alerts
        if "startup" in target and any(target.endswith(e) for e in exts):
            alerts.append(Alert(
                rule_name="Startup Folder Drop", severity="high",
                mitre_tactic="Persistence", mitre_technique="T1547.001",
                description=f"File dropped in startup folder on {ev.computer}: {target}",
                explanation="Files in the Startup folder execute at logon. Simple but effective persistence.",
                confidence="high",
                investigate_next=f"Retrieve and analyze the dropped file. Check which process created it (parent process).",
                event=ev, evidence={"file": target, "evidence_strength": "high"},
            ))

    if ev.event_id == 4720:
        if id(ev) in grouped_account_event_ids:
            return alerts
        new_acct = ev.target_user or ""
        created_by = ev.subject_user or ""
        sam_account = (ed.get("SamAccountName", "") or new_acct).strip()
        if sam_account.endswith("$"):
            return alerts
        alerts.append(Alert(
            rule_name="User Account Created", severity="medium",
            mitre_tactic="Persistence", mitre_technique="T1136.001",
            description=f"Account '{new_acct}' created by {created_by} on {ev.computer}",
            explanation="New accounts may be backdoors. Verify against change management records.",
            confidence="low",
            investigate_next=f"Confirm '{new_acct}' was authorized. Check if it was added to any privileged groups. Check if it has logged on.",
            event=ev, evidence={"new_account": new_acct, "created_by": created_by, "evidence_strength": "medium"},
        ))

    if ev.event_id in (4728, 4732, 4756):
        if id(ev) in grouped_account_event_ids:
            return alerts
        member = _resolve_member_identity(ed.get("MemberName", ""), ed.get("MemberSid", "")) or ev.target_user
        group = _resolve_group_identity(ed.get("TargetUserName", ""), ed.get("TargetSid", ""), ed.get("TargetDomainName", ""))
        changed_by = ev.subject_user or ""
        is_sensitive = _is_sensitive_group(group)
        if is_sensitive:
            alerts.append(Alert(
                rule_name="Member Added to Sensitive Group", severity="critical",
                mitre_tactic="Persistence", mitre_technique="T1098",
                description=f"'{member}' added to '{group}' by {changed_by} on {ev.computer}",
                explanation="Adding users to admin groups grants persistent elevated access. This is a critical privilege escalation if unauthorized.",
                confidence="high",
                investigate_next=f"Verify with {changed_by} if this was authorized. Check '{member}' for recent suspicious activity. Review group membership changes in the last 24h.",
                event=ev, evidence={"member": member, "group": group, "changed_by": changed_by, "evidence_strength": "high"},
            ))

    return alerts
