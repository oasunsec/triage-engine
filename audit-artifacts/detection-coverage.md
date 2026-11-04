# Detection coverage audit

This is an evidence inventory, not a statement of complete ATT&CK coverage.

- Techniques observed: 98
- Mapped: 97
- Telemetry-supported: 93
- Synthetic validation: 12
- Validated public EVTX: 0
- Benign regression: 1
- Missing required benchmark files: 0
- Skipped public-sample tests: 218

## Technique evidence

| Technique | States | Event IDs | Validation evidence |
| --- | --- | --- | --- |
| T1003 | validated_synthetic | — | tests/test_coverage_audit.py:test_normalization_extracts_uppercase_attack_ids, tests/test_html_report.py:test_phase_42_report_sections_are_present |
| T1003.001 | mapped, telemetry_supported, validated_synthetic | 1, 8, 10, 11, 13, 3001, 4656, 4663, 4673, 4688, 4798 | tests/test_case_metrics.py:test_lsass_memory_access_findings_group_into_one_incident |
| T1003.002 | mapped, telemetry_supported | 1, 4624, 4672, 4688, 4794, 5145 | — |
| T1003.003 | mapped, telemetry_supported | 325, 326, 327 | — |
| T1003.004 | mapped, telemetry_supported | 12, 13 | — |
| T1003.006 | mapped, telemetry_supported | 1, 4662, 4688, 4794 | — |
| T1016 | mapped, telemetry_supported | 1, 4104, 4688, 6004 | — |
| T1018 | mapped, telemetry_supported | 5145 | — |
| T1021 | mapped, telemetry_supported | 1, 4624, 4648, 4688, 4697, 4778, 5140, 7045 | — |
| T1021.001 | mapped, telemetry_supported | 1, 11, 1149, 4104, 4624, 4648, 4688, 4697, 4778, 5140, 7045 | — |
| T1021.002 | mapped, telemetry_supported | 1, 11, 12, 13, 17, 18, 4104, 4624, 4648, 4688, 4697, 4778, 5140, 5145, 7045 | — |
| T1021.003 | mapped, telemetry_supported | 1, 3, 4688 | — |
| T1021.004 | mapped, telemetry_supported | 1, 4, 4104, 4688 | — |
| T1021.006 | mapped, telemetry_supported, validated_synthetic | 1, 4624, 4648, 4688, 4697, 4778, 5140, 7045 | tests/test_regressions.py:test_winrm_process_tree_detection |
| T1027 | mapped | — | — |
| T1046 | mapped, telemetry_supported | 4624 | — |
| T1047 | mapped, telemetry_supported, validated_synthetic | 1, 3, 7, 12, 13, 4624, 4648, 4688, 4697, 4778, 5140, 7045 | tests/test_regressions.py:test_wmi_remote_execution_process_tree_detection |
| T1053.005 | mapped, telemetry_supported | 1, 11, 13, 19, 20, 21, 4657, 4688, 4697, 4698, 4699, 4702, 4720, 4728, 4732, 4756, 7045 | — |
| T1055 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1055.003 | mapped, telemetry_supported | 1, 2, 7, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1055.012 | mapped, telemetry_supported | 1, 10, 12, 13 | — |
| T1056 | mapped | — | — |
| T1056.001 | mapped, telemetry_supported | 13 | — |
| T1059 | mapped, telemetry_supported, validated_synthetic | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | tests/test_benign_regressions.py:_make_alert, tests/test_benign_regressions.py:test_rule_suppression_matches_exact_codex_encoded_powershell_chain, tests/test_case_metrics.py:_make_correlate_alert |
| T1059.001 | mapped, validated_synthetic, benign_regression | — | tests/test_coverage_audit.py:test_normalization_extracts_uppercase_attack_ids, tests/test_html_report.py:test_phase_42_report_sections_are_present, tests/test_sigma_support.py:test_sigma_rule_matches_as_signal_only |
| T1068 | mapped | — | — |
| T1069 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1069.001 | mapped, telemetry_supported | 4799 | — |
| T1070.001 | mapped, telemetry_supported | 1, 2, 8, 10, 25, 1102, 4104, 4616, 4688, 4697, 4719, 5001, 5010, 5012, 7040, 7045 | — |
| T1070.006 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1087 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1087.001 | mapped, telemetry_supported, validated_synthetic | 4798 | tests/test_benign_regressions.py:test_rule_suppression_can_match_evidence_list_fields |
| T1098 | mapped, telemetry_supported, validated_synthetic | 1, 11, 13, 19, 20, 21, 4657, 4662, 4688, 4697, 4698, 4702, 4720, 4723, 4724, 4728, 4732, 4733, 4756, 4781, 4794, 5136, 5145, 7045, 33205 | tests/test_benign_regressions.py:test_rule_suppression_can_match_user_wildcards |
| T1105 | mapped, telemetry_supported | 1, 2, 8, 11, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1110 | mapped, telemetry_supported | 4740 | — |
| T1110.001 | mapped, telemetry_supported | 4625 | — |
| T1110.003 | mapped, telemetry_supported | 4625, 4648, 4768, 4771, 18456 | — |
| T1112 | mapped, telemetry_supported | 13 | — |
| T1127 | mapped, telemetry_supported | 1, 4688 | — |
| T1134 | mapped, telemetry_supported | 1, 4611, 4624, 4648, 4672, 4673, 4688, 4704, 4717 | — |
| T1134.001 | mapped, telemetry_supported, validated_synthetic | 1, 3, 8, 10, 17, 18, 4688 | tests/test_case_metrics.py:test_remote_credential_sequence_emits_with_context_finding |
| T1134.005 | mapped, telemetry_supported | 4765 | — |
| T1135 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1136 | mapped, telemetry_supported | 12, 13 | — |
| T1136.001 | mapped, telemetry_supported, validated_synthetic | 1, 11, 13, 19, 20, 21, 4657, 4688, 4697, 4698, 4702, 4720, 4722, 4726, 4728, 4732, 4756, 7045 | tests/test_benign_regressions.py:test_rule_suppression_can_match_evidence_fields |
| T1140 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1187 | mapped, telemetry_supported | 5, 6 | — |
| T1197 | mapped, telemetry_supported | 1, 3, 11, 13, 19, 20, 21, 59, 60, 61, 4657, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4756, 7045 | — |
| T1201 | mapped, telemetry_supported | 1, 4661, 4688 | — |
| T1202 | mapped, telemetry_supported | 1, 4688 | — |
| T1204 | mapped, telemetry_supported | 1116 | — |
| T1207 | mapped, telemetry_supported | 4662, 4742 | — |
| T1210 | mapped, telemetry_supported | 6 | — |
| T1218 | mapped, telemetry_supported | 1, 4688 | — |
| T1218.004 | mapped, telemetry_supported | 1, 7, 4688 | — |
| T1218.005 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1218.007 | mapped, telemetry_supported | 1, 13, 4688 | — |
| T1218.010 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1218.011 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1220 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1482 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1484.001 | mapped, telemetry_supported | 4739, 5136 | — |
| T1505.001 | mapped, telemetry_supported | 15281, 15457, 18454, 33205 | — |
| T1505.003 | mapped, telemetry_supported | 1, 10, 4688 | — |
| T1543.003 | mapped, telemetry_supported, validated_synthetic | 1, 11, 13, 19, 20, 21, 4104, 4657, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4756, 7045 | tests/test_benign_regressions.py:test_rule_suppression_can_match_service_and_command_line_patterns, tests/test_benign_regressions.py:test_rule_suppression_matches_exact_microsoft_defender_driver_path, tests/test_benign_regressions.py:test_rule_suppression_matches_lenovo_tempinst_driver_path, tests/test_benign_regressions.py:test_service_allowlist_matches_parenthetical_service_alias, tests/test_benign_regressions.py:test_service_allowlist_supports_wildcards_for_versioned_services |
| T1546 | mapped, telemetry_supported | 1, 11, 13, 19, 20, 21, 4657, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4756, 7045 | — |
| T1546.003 | mapped, telemetry_supported | 1, 11, 13, 19, 20, 21, 4657, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4756, 5859, 5860, 5861, 7045 | — |
| T1546.008 | mapped, telemetry_supported | 1, 4688 | — |
| T1546.011 | mapped, telemetry_supported | 1, 11, 13 | — |
| T1546.015 | mapped, telemetry_supported, validated_synthetic | 13 | tests/test_regressions.py:test_com_hijack_detection_from_sysmon_registry_events |
| T1547.001 | mapped, telemetry_supported | 1, 11, 13, 19, 20, 21, 4657, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4756, 7045 | — |
| T1547.002 | mapped, telemetry_supported | 11 | — |
| T1548.002 | mapped, telemetry_supported | 1, 7, 11, 12, 13, 4688 | — |
| T1550 | mapped, telemetry_supported | 17, 18 | — |
| T1550.002 | mapped, telemetry_supported | 1, 4624, 4648, 4672, 4688, 4697, 4778, 5140, 7045 | — |
| T1552.001 | mapped, telemetry_supported | 11, 4663 | — |
| T1553.003 | mapped, telemetry_supported | 1, 4688 | — |
| T1555 | mapped, telemetry_supported | 10, 5145 | — |
| T1555.003 | mapped, telemetry_supported | 11, 4663 | — |
| T1555.004 | mapped, telemetry_supported | 5376, 5379, 5381, 5382 | — |
| T1555.005 | mapped, telemetry_supported | 8, 10 | — |
| T1556 | mapped, telemetry_supported | 4624, 4625 | — |
| T1557 | mapped, telemetry_supported | 4624 | — |
| T1558.001 | mapped, telemetry_supported | 1, 4104, 4688, 4768, 4769 | — |
| T1558.002 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1558.003 | mapped, telemetry_supported | 4769 | — |
| T1558.004 | mapped, telemetry_supported | 4768 | — |
| T1560.001 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1562.001 | mapped, telemetry_supported | 1, 2, 3, 8, 12, 13, 17, 18, 25, 1102, 4104, 4616, 4688, 4719, 4876, 4877, 4885, 5001, 5010, 5012, 5123, 5124, 7040 | — |
| T1562.002 | mapped, telemetry_supported | 1, 2, 8, 25, 1102, 4104, 4616, 4688, 4719, 5001, 5010, 5012, 7040 | — |
| T1562.004 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1564.002 | mapped, telemetry_supported | 1, 12, 13, 4688, 4720 | — |
| T1565.001 | mapped, telemetry_supported | 11 | — |
| T1572 | mapped, telemetry_supported | 1, 3, 13, 4624, 4688, 5156 | — |
| T1574 | mapped, telemetry_supported | 13 | — |
| T1574.011 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1574.012 | mapped, telemetry_supported | 1, 4104, 4688 | — |
| T1649 | mapped, telemetry_supported | 4886, 4887, 4888, 4898, 4899, 4900 | — |

## Required benchmark paths

All required benchmark files were present.

## Guardrails

- This is an evidence inventory, not a claim of complete ATT&CK coverage.
- Technique-level validation requires an explicit ATT&CK ID in a test, manifest, or completed benchmark report.
- Public EVTX availability is not validation; only a passed completed benchmark report sets validated_public_EVTX.
- Telemetry-supported means an event-ID comparison was found in the same detector function, not that every variant is observable.
