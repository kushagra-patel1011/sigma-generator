# Validation sample (round 1, Windows)

Drawn by `python -m tools.validation draw` under [the protocol](../validation-protocol.md).

- Seed: `9eb19300d089bf6766b9090407225a64fda3176e` (the commit that added the protocol)
- ATT&CK 19.2, sha256 `dc1639caa5501d72...`
- Atomic Red Team commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`

| Tier | Windows default rules | Eligible | Drawn |
|---|---|---|---|
| strong | 76 | 63 | 17 |
| moderate | 123 | 80 | 17 |
| weak | 123 | 60 | 16 |

## Strong (17 rules, 74 ART tests)

| # | Technique | Logsource | Analytic | ART tests | Rule |
|---|---|---|---|---|---|
| 1 | T1003.004 LSA Secrets | category:process_creation | AN1212 | 2 | [6a13e96c](rules/t1003_004_process_creation_lsa_secrets.yml) |
| 2 | T1056.001 Keylogging | category:process_access | AN0243 | 1 | [3215070d](rules/t1056_001_process_access_keylogging.yml) |
| 3 | T1218.002 Control Panel | category:process_creation | AN0558 | 1 | [30563887](rules/t1218_002_process_creation_control_panel.yml) |
| 4 | T1574.011 Services Registry Permissions Weakness | service:security | AN1195 | 2 | [ecf75ac4](rules/t1574_011_security_services_registry_permissions_weakness.yml) |
| 5 | T1216.002 SyncAppvPublishingServer | category:process_creation | AN1220 | 1 | [57c3dfe5](rules/t1216_002_process_creation_syncappvpublishingserver.yml) |
| 6 | T1546.003 Windows Management Instrumentation Event Subscription | category:process_creation | AN0236 | 4 | [d23e9d0c](rules/t1546_003_process_creation_windows_management_instrumentation_event.yml) |
| 7 | T1059.001 PowerShell | category:process_creation | AN1252 | 21 | [88c4159b](rules/t1059_001_process_creation_powershell.yml) |
| 8 | T1555.004 Windows Credential Manager | category:process_creation | AN0378 | 2 | [0f52c335](rules/t1555_004_process_creation_windows_credential_manager.yml) |
| 9 | T1036.002 Right-to-Left Override | category:process_creation | AN1461 | 2 | [e2f42587](rules/t1036_002_process_creation_right_to_left_override.yml) |
| 10 | T1053.005 Scheduled Task | category:process_creation | AN1221 | 14 | [10210396](rules/t1053_005_process_creation_scheduled_task.yml) |
| 11 | T1197 BITS Jobs | category:process_creation | AN0274 | 4 | [c52008b8](rules/t1197_process_creation_bits_jobs.yml) |
| 12 | T1564.006 Run Virtual Instance | category:process_creation | AN0909 | 3 | [314e8666](rules/t1564_006_process_creation_run_virtual_instance.yml) |
| 13 | T1547.004 Winlogon Helper DLL | category:process_creation | AN1133 | 5 | [b82c5276](rules/t1547_004_process_creation_winlogon_helper_dll.yml) |
| 14 | T1654 Log Enumeration | category:process_creation | AN0705 | 2 | [b1c52a46](rules/t1654_process_creation_log_enumeration.yml) |
| 15 | T1059.005 Visual Basic | category:process_creation | AN0209 | 3 | [dbe001f9](rules/t1059_005_process_creation_visual_basic.yml) |
| 16 | T1021.003 Distributed Component Object Model | category:network_connection | AN0791 | 2 | [ab1526a3](rules/t1021_003_network_connection_distributed_component_object_model.yml) |
| 17 | T1201 Password Policy Discovery | category:process_creation | AN0455 | 5 | [660ccad6](rules/t1201_process_creation_password_policy_discovery.yml) |

Substitution queue, in order: T1560, T1531, T1115, T1087.001, T1057, T1547.002, T1056.004, T1049, T1546.011, T1546.007, T1559, T1003.002, T1505.005, T1134.004, T1686.003, T1202, T1125, T1003.001, T1546.012, T1124, T1070.005, T1047, T1222.001, T1120, T1680, T1132.001, T1505.004, T1216, T1218.009, T1087.002, T1220, T1018, T1007, T1555, T1134.001, T1016.002, T1134.002, T1686, T1135, T1216.001, T1685.005, T1218.008, T1003.003, T1563.002, T1543.003, T1560.001

## Moderate (17 rules, 144 ART tests)

| # | Technique | Logsource | Analytic | ART tests | Rule |
|---|---|---|---|---|---|
| 1 | T1003.005 Cached Domain Credentials | service:security | AN1417 | 1 | [85a2c616](rules/t1003_005_security_cached_domain_credentials.yml) |
| 2 | T1112 Modify Registry | category:registry_set | AN0781 | 92 | [88411e63](rules/t1112_registry_set_modify_registry.yml) |
| 3 | T1556.002 Password Filter DLL | service:security | AN1303 | 2 | [b4ca9903](rules/t1556_002_security_password_filter_dll.yml) |
| 4 | T1546.008 Accessibility Features | category:file_event | AN0094 | 10 | [3f5e8d5c](rules/t1546_008_file_event_accessibility_features.yml) |
| 5 | T1566.002 Spearphishing Link | category:process_creation | AN0298 | 1 | [a77eb500](rules/t1566_002_process_creation_spearphishing_link.yml) |
| 6 | T1136.001 Local Account | category:process_creation | AN1235 | 4 | [49de6a3a](rules/t1136_001_process_creation_local_account.yml) |
| 7 | T1546.013 PowerShell Profile | category:process_creation | AN1245 | 2 | [4678206d](rules/t1546_013_process_creation_powershell_profile.yml) |
| 8 | T1486 Data Encrypted for Impact | category:process_creation | AN0602 | 4 | [29398088](rules/t1486_process_creation_data_encrypted_for_impact.yml) |
| 9 | T1547.005 Security Support Provider | service:security | AN1495 | 2 | [f03abba9](rules/t1547_005_security_security_support_provider.yml) |
| 10 | T1218.003 CMSTP | category:network_connection | AN0932 | 2 | [60339c35](rules/t1218_003_network_connection_cmstp.yml) |
| 11 | T1222 File and Directory Permissions Modification | category:process_creation | AN0834 | 3 | [e8cdcf05](rules/t1222_process_creation_file_and_directory_permissions_modificat.yml) |
| 12 | T1546.001 Change Default File Association | category:registry_set | AN0170 | 1 | [c31c2362](rules/t1546_001_registry_set_change_default_file_association.yml) |
| 13 | T1615 Group Policy Discovery | category:process_creation | AN0152 | 5 | [68407883](rules/t1615_process_creation_group_policy_discovery.yml) |
| 14 | T1129 Shared Modules | category:image_load | AN0052 | 1 | [7be74a91](rules/t1129_image_load_shared_modules.yml) |
| 15 | T1095 Non-Application Layer Protocol | category:network_connection | AN1254 | 4 | [9239133a](rules/t1095_network_connection_non_application_layer_protocol.yml) |
| 16 | T1567.004 Exfiltration Over Webhook | category:process_creation | AN0436 | 2 | [24598a62](rules/t1567_004_process_creation_exfiltration_over_webhook.yml) |
| 17 | T1218.004 InstallUtil | category:ps_script | AN0388 | 8 | [2e161ae2](rules/t1218_004_ps_script_installutil.yml) |

Substitution queue, in order: T1048.003, T1137.002, T1567.003, T1027.018, T1137.005, T1127.001, T1106, T1048, T1036.007, T1539, T1548.002, T1053.002, T1110.002, T1114.001, T1006, T1546.002, T1547.012, T1016, T1218.001, T1559.002, T1059.003, T1204.002, T1547.008, T1484.001, T1547.003, T1546.009, T1552.006, T1553.006, T1140, T1564.001, T1055.001, T1652, T1547.014, T1569.002, T1572, T1072, T1012, T1127, T1614.001, T1688, T1055.004, T1558.001, T1218, T1574.009, T1490, T1552.004, T1218.011, T1567.002, T1685.001, T1547.001, T1547.010, T1505.003, T1556.001, T1553.003, T1217, T1546.015, T1137.004, T1074.001, T1546.010, T1055, T1574.008, T1491.001, T1564.003

## Weak (16 rules, 62 ART tests)

| # | Technique | Logsource | Analytic | ART tests | Rule |
|---|---|---|---|---|---|
| 1 | T1025 Data from Removable Media | service:security | AN1410 | 1 | [6a9a1ad5](rules/t1025_security_data_from_removable_media.yml) |
| 2 | T1518 Software Discovery | category:process_creation | AN1100 | 5 | [8d55cdb8](rules/t1518_process_creation_software_discovery.yml) |
| 3 | T1552 Unsecured Credentials | category:file_event | AN1153 | 1 | [82115d40](rules/t1552_file_event_unsecured_credentials.yml) |
| 4 | T1574.001 DLL | category:file_event | AN0577 | 7 | [fd2b80bb](rules/t1574_001_file_event_dll.yml) |
| 5 | T1113 Screen Capture | category:process_creation | AN0980 | 4 | [cdeee036](rules/t1113_process_creation_screen_capture.yml) |
| 6 | T1110.003 Password Spraying | service:security | AN1336 | 6 | [8be304df](rules/t1110_003_security_password_spraying.yml) |
| 7 | T1620 Reflective Code Loading | category:process_creation | AN0838 | 3 | [4d5fe3c5](rules/t1620_process_creation_reflective_code_loading.yml) |
| 8 | T1564 Hide Artifacts | category:file_event | AN1384 | 5 | [32aea03e](rules/t1564_file_event_hide_artifacts.yml) |
| 9 | T1218.005 Mshta | category:process_creation | AN1397 | 10 | [d8a676a5](rules/t1218_005_process_creation_mshta.yml) |
| 10 | T1137.001 Office Template Macros | category:file_event | AN1436 | 1 | [bc89f8a9](rules/t1137_001_file_event_office_template_macros.yml) |
| 11 | T1016.001 Internet Connection Discovery | category:process_creation | AN1015 | 4 | [56f56d20](rules/t1016_001_process_creation_internet_connection_discovery.yml) |
| 12 | T1689 Downgrade Attack | category:process_creation | AN0995 | 2 | [a59e284d](rules/t1689_process_creation_downgrade_attack.yml) |
| 13 | T1071.001 Web Protocols | category:network_connection | AN0075 | 2 | [82a6a959](rules/t1071_001_network_connection_web_protocols.yml) |
| 14 | T1482 Domain Trust Discovery | category:process_creation | AN0016 | 8 | [3023fbe2](rules/t1482_process_creation_domain_trust_discovery.yml) |
| 15 | T1091 Replication Through Removable Media | category:file_event | AN0841 | 1 | [62f44e1f](rules/t1091_file_event_replication_through_removable_media.yml) |
| 16 | T1003.006 DCSync | service:security | AN1632 | 2 | [ed182c75](rules/t1003_006_security_dcsync.yml) |

Substitution queue, in order: T1219, T1136.002, T1564.012, T1497.001, T1001.002, T1558.004, T1056.002, T1221, T1553.005, T1078.003, T1574.012, T1564.004, T1542.001, T1550.003, T1041, T1071.004, T1071, T1059, T1137.006, T1218.010, T1020, T1134.005, T1078.001, T1558.003, T1090.003, T1137, T1037.001, T1207, T1010, T1571, T1021.002, T1566.001, T1550.002, T1021.001, T1030, T1552.002, T1110.001, T1218.007, T1070.006, T1039, T1055.012, T1558.002, T1110.004, T1005
