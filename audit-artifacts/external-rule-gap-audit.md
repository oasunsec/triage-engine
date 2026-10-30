# External rule gap audit

This report compares metadata references from local third-party rule mirrors with the engine coverage inventory. A reference is not a validation result and no upstream rule content is imported.

- Sources: 3 (0 optional missing; 0 required missing)
- Windows rule references: 6960
- Techniques referenced: 383
- High-priority unmapped gaps: 275
- Medium-priority review items: 100

## Prioritized gaps

| Priority | Technique | Classification | External event IDs |
| --- | --- | --- | --- |
| high | T1001.003 | unmapped_engine_gap | 1, 11, 4688, 5136 |
| high | T1003 | unmapped_engine_gap | 1, 3, 4, 5, 7, 10, 11, 12, 13, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4104, 4624, 4625, 4648, 4656, 4657, 4662, 4663, 4688, 4776, 5136, 5145, 5382, 7045 |
| high | T1003.005 | unmapped_engine_gap | 1, 3, 6, 11, 17, 18, 4624, 4625, 4648, 4688, 4697, 7045 |
| high | T1003.008 | unmapped_engine_gap | — |
| high | T1005 | unmapped_engine_gap | 1, 17, 18, 1001, 4688 |
| high | T1006 | unmapped_engine_gap | 9, 4104 |
| high | T1007 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1008 | unmapped_engine_gap | 11, 13, 4657 |
| high | T1010 | unmapped_engine_gap | 1, 4656, 4688 |
| high | T1012 | unmapped_engine_gap | 1, 4104, 4656, 4663, 4688, 4799, 5145 |
| high | T1016.001 | unmapped_engine_gap | — |
| high | T1020 | unmapped_engine_gap | 4104 |
| high | T1021.005 | unmapped_engine_gap | 1, 4688 |
| high | T1027.001 | unmapped_engine_gap | 5038, 6281 |
| high | T1027.002 | unmapped_engine_gap | 7 |
| high | T1027.003 | unmapped_engine_gap | 1, 4688 |
| high | T1027.004 | unmapped_engine_gap | 1, 11, 4688 |
| high | T1027.005 | unmapped_engine_gap | 1, 4656, 4658, 4663, 4688 |
| high | T1027.006 | unmapped_engine_gap | — |
| high | T1027.009 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1027.010 | unmapped_engine_gap | 1, 13, 4104, 4657, 4688 |
| high | T1027.013 | unmapped_engine_gap | — |
| high | T1027.015 | unmapped_engine_gap | — |
| high | T1033 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1035 | unmapped_engine_gap | 7045 |
| high | T1036 | unmapped_engine_gap | 1, 7, 11, 4624, 4648, 4688, 4720, 4768, 4769, 4781, 5379 |
| high | T1036.001 | unmapped_engine_gap | — |
| high | T1036.002 | unmapped_engine_gap | 1, 11, 4688 |
| high | T1036.003 | unmapped_engine_gap | 1, 7, 11, 13, 400, 4104, 4657, 4688 |
| high | T1036.004 | unmapped_engine_gap | 1, 4688, 4799 |
| high | T1036.005 | unmapped_engine_gap | 1, 7, 11, 1119, 4688 |
| high | T1036.007 | unmapped_engine_gap | 1, 11, 4688 |
| high | T1036.009 | unmapped_engine_gap | — |
| high | T1037 | unmapped_engine_gap | 5136, 5145 |
| high | T1037.001 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1039 | unmapped_engine_gap | 1, 4688, 5140, 5145 |
| high | T1041 | unmapped_engine_gap | 1, 3, 4688 |
| high | T1048 | unmapped_engine_gap | 1, 6, 22, 4104, 4688, 4697, 7045 |
| high | T1048.001 | unmapped_engine_gap | 1, 4688 |
| high | T1048.003 | unmapped_engine_gap | 1, 3, 4104, 4688, 5156 |
| high | T1049 | unmapped_engine_gap | 1, 400, 4103, 4688 |
| high | T1050 | unmapped_engine_gap | 7045 |
| high | T1052 | unmapped_engine_gap | — |
| high | T1052.001 | unmapped_engine_gap | — |
| high | T1053 | unmapped_engine_gap | 1, 11, 13, 4657, 4688, 4701, 4702, 5136, 5145 |
| high | T1053.002 | unmapped_engine_gap | 1, 4688, 5145 |
| high | T1055.001 | unmapped_engine_gap | 1, 2, 8, 10, 4688 |
| high | T1055.002 | unmapped_engine_gap | 2, 10 |
| high | T1055.004 | unmapped_engine_gap | — |
| high | T1055.011 | unmapped_engine_gap | 10 |
| high | T1056.002 | unmapped_engine_gap | 1, 7 |
| high | T1056.004 | unmapped_engine_gap | 1, 4688 |
| high | T1057 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1059.004 | unmapped_engine_gap | — |
| high | T1059.005 | unmapped_engine_gap | 1, 7, 8, 11, 12, 13, 14, 19, 20, 21, 4104, 4657, 4688, 5861, 8003, 8004, 8006, 8007, 8021, 8022, 8024, 8025 |
| high | T1059.006 | unmapped_engine_gap | 1, 11, 4688, 8003, 8004, 8006, 8007, 8021, 8022, 8024, 8025 |
| high | T1059.010 | unmapped_engine_gap | — |
| high | T1069.002 | unmapped_engine_gap | 1, 5, 11, 18, 30, 4103, 4104, 4661, 4662, 4688 |
| high | T1070 | unmapped_engine_gap | 1, 2, 7, 12, 23, 26, 104, 1102, 4104, 4688, 4719 |
| high | T1070.003 | unmapped_engine_gap | 1, 12, 4103, 4104, 4688 |
| high | T1070.004 | unmapped_engine_gap | 1, 12, 23, 26, 524, 4104, 4656, 4657, 4658, 4663, 4688 |
| high | T1070.005 | unmapped_engine_gap | 1, 13, 4104, 4657, 4688 |
| high | T1070.008 | unmapped_engine_gap | 4104 |
| high | T1071 | unmapped_engine_gap | 1, 7, 257, 4688 |
| high | T1071.001 | unmapped_engine_gap | 1, 3, 22, 4104, 4688, 5156 |
| high | T1071.004 | unmapped_engine_gap | 1, 3, 12, 13, 14, 22, 3008, 4104, 4657, 4688, 4698, 5156, 7045 |
| high | T1072 | unmapped_engine_gap | 1, 2, 3, 865, 866, 867, 868, 882, 4688 |
| high | T1074 | unmapped_engine_gap | — |
| high | T1074.001 | unmapped_engine_gap | 1, 4103, 4104, 4688 |
| high | T1074.002 | unmapped_engine_gap | — |
| high | T1076 | unmapped_engine_gap | 1, 4688 |
| high | T1077 | unmapped_engine_gap | 18 |
| high | T1078.001 | unmapped_engine_gap | 1, 4624, 4688 |
| high | T1078.002 | unmapped_engine_gap | 1, 4104, 4624, 4648, 4662, 4688, 4738, 4768, 4769, 5136, 5137 |
| high | T1078.003 | unmapped_engine_gap | 4624 |
| high | T1082 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1083 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1086 | unmapped_engine_gap | 7 |
| high | T1087.002 | unmapped_engine_gap | 1, 5, 11, 18, 30, 4103, 4104, 4661, 4662, 4688, 5156 |
| high | T1090.001 | unmapped_engine_gap | 1, 4688, 5156 |
| high | T1090.002 | unmapped_engine_gap | 3, 5156 |
| high | T1090.003 | unmapped_engine_gap | 1, 22, 3008, 4688 |
| high | T1090.004 | unmapped_engine_gap | 3 |
| high | T1091 | unmapped_engine_gap | 6416 |
| high | T1095 | unmapped_engine_gap | 1, 400, 4103, 4688 |
| high | T1096 | unmapped_engine_gap | 15 |
| high | T1098.002 | unmapped_engine_gap | — |
| high | T1098.007 | unmapped_engine_gap | — |
| high | T1099 | unmapped_engine_gap | 2 |
| high | T1102 | unmapped_engine_gap | 1, 3, 4688 |
| high | T1102.001 | unmapped_engine_gap | 3 |
| high | T1102.002 | unmapped_engine_gap | 1, 3, 4688 |
| high | T1104 | unmapped_engine_gap | 1, 4688 |
| high | T1106 | unmapped_engine_gap | 1, 5, 10, 17, 18, 4104, 4624, 4625, 4648, 4688 |
| high | T1110.002 | unmapped_engine_gap | 1, 4688 |
| high | T1113 | unmapped_engine_gap | 1, 7, 12, 13, 4104, 4657, 4688 |
| high | T1114 | unmapped_engine_gap | 1, 4624, 4625, 4688, 4776 |
| high | T1114.001 | unmapped_engine_gap | 4104 |
| high | T1114.002 | unmapped_engine_gap | — |
| high | T1114.003 | unmapped_engine_gap | 4104 |
| high | T1115 | unmapped_engine_gap | 1, 4103, 4688 |
| high | T1117 | unmapped_engine_gap | 1, 4688 |
| high | T1119 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1120 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1123 | unmapped_engine_gap | 1, 12, 13, 14, 4656, 4657, 4663, 4688 |
| high | T1124 | unmapped_engine_gap | 1, 4688 |
| high | T1127.001 | unmapped_engine_gap | 1, 3, 8, 4688, 5156 |
| high | T1128 | unmapped_engine_gap | 13, 4657 |
| high | T1129 | unmapped_engine_gap | 7 |
| high | T1130 | unmapped_engine_gap | — |
| high | T1132.001 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1133 | unmapped_engine_gap | 1, 2, 11, 13, 23, 26, 4624, 4625, 4657, 4688 |
| high | T1134.002 | unmapped_engine_gap | 1, 6, 4624, 4634, 4648, 4688, 4697, 7045 |
| high | T1134.003 | unmapped_engine_gap | 1, 4624, 4634, 4648, 4688 |
| high | T1134.004 | unmapped_engine_gap | 1, 4688 |
| high | T1136.002 | unmapped_engine_gap | 1, 11, 4104, 4688, 4720, 4741, 5136, 5137, 7045 |
| high | T1137 | unmapped_engine_gap | 11, 13, 4657 |
| high | T1137.001 | unmapped_engine_gap | — |
| high | T1137.002 | unmapped_engine_gap | 12, 13, 14, 4657 |
| high | T1137.003 | unmapped_engine_gap | 11 |
| high | T1137.004 | unmapped_engine_gap | — |
| high | T1137.006 | unmapped_engine_gap | 11, 13, 4104, 4657 |
| high | T1176 | unmapped_engine_gap | 1 |
| high | T1176.001 | unmapped_engine_gap | 1, 4688 |
| high | T1185 | unmapped_engine_gap | 1, 4624, 4688 |
| high | T1189 | unmapped_engine_gap | 22 |
| high | T1190 | unmapped_engine_gap | 1, 4, 11, 1033, 4625, 4688, 7053, 33205 |
| high | T1195 | unmapped_engine_gap | 11 |
| high | T1195.001 | unmapped_engine_gap | 11 |
| high | T1195.002 | unmapped_engine_gap | 1, 11, 22, 4688 |
| high | T1200 | unmapped_engine_gap | 2003, 2100, 2102, 6416, 6423 |
| high | T1203 | unmapped_engine_gap | 1, 3, 11, 13, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4657, 4688, 5156, 7053 |
| high | T1204.001 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1204.002 | unmapped_engine_gap | 1, 7, 10, 11, 13, 400, 603, 854, 4657, 4688, 8003, 8004, 8006, 8007, 8021, 8022, 8024, 8025 |
| high | T1204.004 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1208 | unmapped_engine_gap | 1, 4688 |
| high | T1211 | unmapped_engine_gap | 1, 1000, 1001, 4688 |
| high | T1212 | unmapped_engine_gap | 1, 675, 4624, 4648, 4688, 4768, 4769, 4771, 4887 |
| high | T1213 | unmapped_engine_gap | 4662 |
| high | T1216 | unmapped_engine_gap | 1, 11, 4104, 4688 |
| high | T1216.001 | unmapped_engine_gap | 1, 4688 |
| high | T1217 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1218.001 | unmapped_engine_gap | 1, 3, 4688, 5156 |
| high | T1218.002 | unmapped_engine_gap | 1, 4688 |
| high | T1218.003 | unmapped_engine_gap | 1, 3, 7, 10, 12, 13, 14, 4657, 4688, 5156 |
| high | T1218.008 | unmapped_engine_gap | 1, 4688 |
| high | T1218.009 | unmapped_engine_gap | 1, 3, 4688, 5156 |
| high | T1218.013 | unmapped_engine_gap | 1, 4688 |
| high | T1218.014 | unmapped_engine_gap | 1, 7, 4688 |
| high | T1219 | unmapped_engine_gap | 1, 3, 11, 22, 4688, 5156 |
| high | T1219.002 | unmapped_engine_gap | 1, 3, 7, 11, 22, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1033, 1115, 1116, 4688, 5156, 7045, 8001 |
| high | T1221 | unmapped_engine_gap | 13, 4657 |
| high | T1222 | unmapped_engine_gap | 4104 |
| high | T1485 | unmapped_engine_gap | 1, 4656, 4658, 4663, 4688, 33205 |
| high | T1489 | unmapped_engine_gap | 1, 141, 142, 1034, 4688, 11724 |
| high | T1491.001 | unmapped_engine_gap | 1, 13, 4104, 4657, 4688 |
| high | T1496 | unmapped_engine_gap | 1, 3, 4688 |
| high | T1497 | unmapped_engine_gap | — |
| high | T1497.001 | unmapped_engine_gap | 4104 |
| high | T1497.003 | unmapped_engine_gap | — |
| high | T1498 | unmapped_engine_gap | 1, 4688 |
| high | T1499 | unmapped_engine_gap | 1000, 6008, 7031, 7034 |
| high | T1499.001 | unmapped_engine_gap | 55 |
| high | T1499.004 | unmapped_engine_gap | 1 |
| high | T1505 | unmapped_engine_gap | — |
| high | T1505.002 | unmapped_engine_gap | 1, 6, 4688 |
| high | T1505.004 | unmapped_engine_gap | 1, 29, 4688 |
| high | T1505.005 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1518 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1518.001 | unmapped_engine_gap | 1, 4103, 4104, 4688 |
| high | T1526 | unmapped_engine_gap | 1, 4688 |
| high | T1528 | unmapped_engine_gap | 1, 11, 17, 18, 4663, 4688 |
| high | T1529 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1531 | unmapped_engine_gap | 4104, 4634, 4647 |
| high | T1539 | unmapped_engine_gap | 1, 4624, 4688 |
| high | T1542.001 | unmapped_engine_gap | 1, 11, 4688 |
| high | T1542.003 | unmapped_engine_gap | 1, 4688 |
| high | T1543 | unmapped_engine_gap | 1, 2, 4, 5, 6, 3023, 3077, 4624, 4648, 4688, 4697, 7045 |
| high | T1546.001 | unmapped_engine_gap | 1, 12, 13, 14, 4657, 4688 |
| high | T1546.002 | unmapped_engine_gap | 1, 11, 12, 13, 14, 4657, 4688 |
| high | T1546.007 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1546.009 | unmapped_engine_gap | 12, 13, 14, 4657 |
| high | T1546.010 | unmapped_engine_gap | 12, 13, 14, 4657 |
| high | T1546.012 | unmapped_engine_gap | 13, 4657 |
| high | T1546.013 | unmapped_engine_gap | 11, 4104 |
| high | T1547 | unmapped_engine_gap | 1, 3, 11, 12, 13, 14, 4624, 4657, 4688, 4776, 5136, 5145 |
| high | T1547.003 | unmapped_engine_gap | 13, 4657 |
| high | T1547.004 | unmapped_engine_gap | 13, 4104, 4657 |
| high | T1547.005 | unmapped_engine_gap | 3, 12, 13, 14, 4624, 4657, 4776 |
| high | T1547.006 | unmapped_engine_gap | — |
| high | T1547.008 | unmapped_engine_gap | 12, 13, 14, 4657 |
| high | T1547.009 | unmapped_engine_gap | 11, 5145 |
| high | T1547.010 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1547.012 | unmapped_engine_gap | — |
| high | T1547.014 | unmapped_engine_gap | 1, 4688 |
| high | T1547.015 | unmapped_engine_gap | 11 |
| high | T1548 | unmapped_engine_gap | 1, 10, 11, 13, 4104, 4624, 4657, 4674, 4688, 5829 |
| high | T1550.003 | unmapped_engine_gap | 1, 3, 4104, 4624, 4625, 4648, 4688, 4768, 4769, 5156 |
| high | T1552 | unmapped_engine_gap | 1, 21, 22, 25, 462, 1149, 4662, 4688, 4778, 5145 |
| high | T1552.002 | unmapped_engine_gap | 1, 4656, 4688, 5145 |
| high | T1552.006 | unmapped_engine_gap | 1, 4688 |
| high | T1553 | unmapped_engine_gap | 1, 6, 4688 |
| high | T1553.002 | unmapped_engine_gap | 6, 4656, 4658, 4663 |
| high | T1553.004 | unmapped_engine_gap | 1, 13, 53, 4104, 4657, 4688 |
| high | T1553.005 | unmapped_engine_gap | 1, 11, 400, 603, 4104, 4663 |
| high | T1553.006 | unmapped_engine_gap | — |
| high | T1554 | unmapped_engine_gap | 11, 22, 4697, 40300, 40301, 40302 |
| high | T1556.002 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1556.007 | unmapped_engine_gap | — |
| high | T1556.008 | unmapped_engine_gap | — |
| high | T1557.001 | unmapped_engine_gap | 1, 2, 6, 22, 4104, 4624, 4625, 4648, 4662, 4688, 5136, 5137, 5145, 10001 |
| high | T1557.003 | unmapped_engine_gap | 4662, 5136, 5137 |
| high | T1558 | unmapped_engine_gap | 3, 5, 11, 16, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4104, 4624, 4625, 4648, 4649, 4672, 4697, 4704, 4705, 4738, 4768, 4769, 4964, 5136, 5156, 14674 |
| high | T1559 | unmapped_engine_gap | 1 |
| high | T1559.001 | unmapped_engine_gap | 3, 10, 22, 5156 |
| high | T1559.002 | unmapped_engine_gap | 13, 4657 |
| high | T1560 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1561 | unmapped_engine_gap | 4673 |
| high | T1562 | unmapped_engine_gap | 1, 12, 13, 14, 400, 4104, 4657, 4688, 4719, 4738, 7040 |
| high | T1562.006 | unmapped_engine_gap | 4719 |
| high | T1562.010 | unmapped_engine_gap | 400 |
| high | T1563 | unmapped_engine_gap | 4688 |
| high | T1563.002 | unmapped_engine_gap | 1, 4688 |
| high | T1564 | unmapped_engine_gap | 1, 4, 11, 13, 16, 255, 4657, 4688 |
| high | T1564.001 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1564.003 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1564.004 | unmapped_engine_gap | 1, 11, 15, 4104, 4688 |
| high | T1564.006 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1564.008 | unmapped_engine_gap | 4104 |
| high | T1565 | unmapped_engine_gap | 4104 |
| high | T1565.002 | unmapped_engine_gap | 4100 |
| high | T1566 | unmapped_engine_gap | 1, 11, 13, 4657, 4688 |
| high | T1566.001 | unmapped_engine_gap | 1, 11, 12, 13, 14, 4657, 4663, 4688, 5379 |
| high | T1566.002 | unmapped_engine_gap | — |
| high | T1567 | unmapped_engine_gap | 1, 3, 4688 |
| high | T1567.001 | unmapped_engine_gap | 3 |
| high | T1567.002 | unmapped_engine_gap | 1, 3, 11, 22, 3008, 4688 |
| high | T1567.003 | unmapped_engine_gap | — |
| high | T1568 | unmapped_engine_gap | — |
| high | T1568.002 | unmapped_engine_gap | 3 |
| high | T1569 | unmapped_engine_gap | 1, 316, 808, 4688, 4697, 5145, 7045 |
| high | T1570 | unmapped_engine_gap | 1, 3, 11, 4104, 4624, 4688, 4697, 5136, 5145, 7045 |
| high | T1571 | unmapped_engine_gap | 3, 4104, 5156 |
| high | T1573 | unmapped_engine_gap | 1, 3, 4104, 4688 |
| high | T1574.001 | unmapped_engine_gap | 1, 7, 11, 12, 13, 150, 770, 771, 1031, 1032, 1033, 1034, 4657, 4688 |
| high | T1574.005 | unmapped_engine_gap | 1, 4688 |
| high | T1574.007 | unmapped_engine_gap | 1, 7, 4688 |
| high | T1574.008 | unmapped_engine_gap | 1, 4688 |
| high | T1574.009 | unmapped_engine_gap | 11 |
| high | T1574.010 | unmapped_engine_gap | 11 |
| high | T1584 | unmapped_engine_gap | 11, 16, 20, 24, 213, 217 |
| high | T1587 | unmapped_engine_gap | 1, 7, 11, 4688 |
| high | T1587.001 | unmapped_engine_gap | 1, 11, 4688 |
| high | T1588 | unmapped_engine_gap | 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116 |
| high | T1588.002 | unmapped_engine_gap | 1, 13, 4657, 4688 |
| high | T1589.002 | unmapped_engine_gap | 4104 |
| high | T1590 | unmapped_engine_gap | 22 |
| high | T1590.001 | unmapped_engine_gap | 1, 4688 |
| high | T1590.002 | unmapped_engine_gap | 1, 2, 6004 |
| high | T1593.003 | unmapped_engine_gap | 1, 4688 |
| high | T1595 | unmapped_engine_gap | 1, 4688 |
| high | T1595.001 | unmapped_engine_gap | 1, 4688 |
| high | T1598.002 | unmapped_engine_gap | 1, 4688 |
| high | T1599.001 | unmapped_engine_gap | 6 |
| high | T1608 | unmapped_engine_gap | 1, 12, 13, 14, 4657, 4688 |
| high | T1614.001 | unmapped_engine_gap | 1, 4688 |
| high | T1615 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1620 | unmapped_engine_gap | 1, 4104, 4688 |
| high | T1622 | unmapped_engine_gap | 1, 4688 |
| high | T1651 | unmapped_engine_gap | — |
| high | T1685 | unmapped_engine_gap | 1, 7, 10, 11, 12, 13, 14, 17, 18, 26, 600, 1000, 1001, 1009, 1119, 3002, 3007, 4104, 4656, 4657, 4663, 4673, 4688, 4738, 5001, 5007, 5010, 5012, 5013, 5101, 5157, 5441, 5447, 7036 |
| high | T1685.001 | unmapped_engine_gap | 1, 7, 10, 11, 12, 13, 14, 29, 4657, 4688, 4719 |
| high | T1685.005 | unmapped_engine_gap | 1, 104, 517, 1102, 4104, 4688, 5858 |
| high | T1686.003 | unmapped_engine_gap | 1, 10, 11, 13, 2002, 2003, 2004, 2005, 2006, 2008, 2009, 2032, 2033, 2052, 2059, 2060, 2071, 2073, 2082, 2083, 2097, 4104, 4657, 4688 |
| high | T1689 | unmapped_engine_gap | 1, 4688 |
| medium | T1003.001 | mapped_without_public_EVTX_validation | 1, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 365, 1000, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 1121, 4104, 4624, 4625, 4648, 4656, 4657, 4663, 4673, 4688, 4697, 5145, 7045 |
| medium | T1003.002 | mapped_without_public_EVTX_validation | 1, 3, 6, 11, 12, 13, 14, 15, 16, 17, 18, 98, 365, 1001, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4104, 4624, 4625, 4648, 4657, 4688, 4697, 4904, 4905, 5145, 7045 |
| medium | T1003.003 | mapped_without_public_EVTX_validation | 1, 11, 216, 325, 326, 327, 4103, 4104, 4624, 4688, 5145 |
| medium | T1003.004 | mapped_without_public_EVTX_validation | 1, 3, 6, 11, 15, 17, 18, 4624, 4625, 4648, 4662, 4688, 4692, 4697, 5145, 7045 |
| medium | T1003.006 | mapped_without_public_EVTX_validation | 1, 3, 6, 15, 4104, 4624, 4625, 4648, 4662, 4688, 4697, 5136, 7045 |
| medium | T1016 | mapped_without_public_EVTX_validation | 1, 3, 22, 4103, 4688, 4689 |
| medium | T1018 | mapped_without_public_EVTX_validation | 1, 4104, 4688, 4689 |
| medium | T1021 | mapped_without_public_EVTX_validation | 1, 3, 4624, 4625, 4648, 4674, 4688, 5145, 5156 |
| medium | T1021.001 | mapped_without_public_EVTX_validation | 1, 3, 13, 4624, 4657, 4688, 4825, 5156 |
| medium | T1021.002 | mapped_without_public_EVTX_validation | 1, 3, 7, 11, 13, 17, 18, 4000, 4104, 4624, 4625, 4657, 4688, 4697, 4776, 5140, 5145, 7045, 31010 |
| medium | T1021.003 | mapped_without_public_EVTX_validation | 1, 7, 11, 4688, 5145 |
| medium | T1021.004 | mapped_without_public_EVTX_validation | 1, 4, 4688 |
| medium | T1021.006 | mapped_without_public_EVTX_validation | 1, 3, 10, 400, 4103, 4104, 4688 |
| medium | T1027 | mapped_without_public_EVTX_validation | 1, 6, 11, 4103, 4104, 4688, 4697, 4799, 5379, 7045 |
| medium | T1040 | mapped_without_public_EVTX_validation | 1, 4104, 4688, 4697 |
| medium | T1046 | mapped_without_public_EVTX_validation | 1, 3, 11, 4104, 4688, 5156 |
| medium | T1047 | mapped_without_public_EVTX_validation | 1, 7, 11, 13, 17, 18, 19, 20, 21, 1121, 4104, 4624, 4657, 4688, 5145, 5861 |
| medium | T1053.005 | mapped_without_public_EVTX_validation | 1, 7, 11, 12, 13, 14, 106, 129, 4104, 4624, 4657, 4688, 4698, 4699, 4701, 4702, 4799, 5136, 5145, 7045 |
| medium | T1055 | mapped_without_public_EVTX_validation | 1, 3, 7, 8, 10, 11, 17, 18, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 1119, 4104, 4688, 5156 |
| medium | T1055.003 | mapped_without_public_EVTX_validation | 8, 10 |
| medium | T1055.012 | mapped_without_public_EVTX_validation | 1, 8, 10, 25, 4688 |
| medium | T1056 | mapped_without_public_EVTX_validation | 22 |
| medium | T1056.001 | mapped_without_public_EVTX_validation | 4104 |
| medium | T1059 | mapped_without_public_EVTX_validation | 1, 2, 5, 7, 11, 22, 1006, 1015, 1116, 1117, 4104, 4624, 4625, 4648, 4674, 4688, 4769, 4776 |
| medium | T1059.001 | mapped_without_public_EVTX_validation | 1, 2, 3, 5, 6, 7, 8, 10, 11, 13, 17, 18, 400, 4103, 4104, 4624, 4625, 4648, 4657, 4688, 4697, 4769, 4799, 5156, 7045, 8003, 8004, 8006, 8007, 8021, 8022, 8024, 8025 |
| medium | T1059.007 | mapped_without_public_EVTX_validation | 1, 8, 11, 13, 4657, 4688, 8003, 8004, 8006, 8007, 8021, 8022, 8024, 8025 |
| medium | T1068 | mapped_without_public_EVTX_validation | 1, 6, 7, 11, 4624, 4648, 4688, 4742, 4768, 4769, 4887, 5136 |
| medium | T1069 | mapped_without_public_EVTX_validation | 1, 5, 18, 4103, 4104, 4662, 4688 |
| medium | T1069.001 | mapped_without_public_EVTX_validation | 1, 11, 4103, 4104, 4688 |
| medium | T1070.001 | mapped_without_public_EVTX_validation | 1, 104, 1102, 4104, 4688, 4719 |
| medium | T1070.006 | mapped_without_public_EVTX_validation | 2, 4104, 4616 |
| medium | T1087 | mapped_without_public_EVTX_validation | 1, 3, 5, 18, 21, 22, 25, 462, 1149, 4103, 4104, 4624, 4625, 4662, 4688, 4776, 4778, 5156 |
| medium | T1087.001 | mapped_without_public_EVTX_validation | 1, 11, 4103, 4104, 4688 |
| medium | T1090 | mapped_without_public_EVTX_validation | 1, 3, 12, 13, 14, 21, 4104, 4657, 4688 |
| medium | T1098 | mapped_without_public_EVTX_validation | 1, 5, 18, 632, 633, 634, 4104, 4624, 4648, 4688, 4704, 4705, 4706, 4728, 4729, 4730, 4732, 4738, 4768, 4769, 4781, 4794, 5136, 5137, 14674 |
| medium | T1105 | mapped_without_public_EVTX_validation | 1, 3, 7, 10, 11, 12, 13, 14, 22, 400, 4104, 4657, 4688, 5156, 5379 |
| medium | T1110 | mapped_without_public_EVTX_validation | 1, 4624, 4625, 4648, 4688, 8004, 18456 |
| medium | T1110.001 | mapped_without_public_EVTX_validation | 1, 4104, 4624, 4688, 31017 |
| medium | T1110.003 | mapped_without_public_EVTX_validation | 4624, 4625, 4648, 4768, 4771, 4776 |
| medium | T1112 | mapped_without_public_EVTX_validation | 1, 3, 7, 12, 13, 14, 4104, 4624, 4657, 4663, 4688, 4698, 5145, 7045 |
| medium | T1125 | declared_event_log_limit | 12, 13, 14, 4657 |
| medium | T1127 | mapped_without_public_EVTX_validation | 1, 8, 11, 4688 |
| medium | T1134 | mapped_without_public_EVTX_validation | 1, 17, 4624, 4634, 4648, 4674, 4688, 5447, 5449 |
| medium | T1134.001 | mapped_without_public_EVTX_validation | 1, 6, 17, 18, 4624, 4688, 4697, 5447, 5449, 7045 |
| medium | T1134.005 | mapped_without_public_EVTX_validation | 4738, 4765, 4766 |
| medium | T1135 | mapped_without_public_EVTX_validation | 1, 4688, 5140, 5145 |
| medium | T1136 | mapped_without_public_EVTX_validation | 4720, 5136, 5137 |
| medium | T1136.001 | mapped_without_public_EVTX_validation | 1, 12, 13, 14, 4104, 4657, 4688, 4720 |
| medium | T1140 | mapped_without_public_EVTX_validation | 1, 13, 4103, 4104, 4657, 4688 |
| medium | T1187 | mapped_without_public_EVTX_validation | 1, 11, 22, 4624, 4625, 4648, 4662, 4688, 4768, 5136, 5137, 5145 |
| medium | T1197 | mapped_without_public_EVTX_validation | 1, 3, 7, 59, 4688, 16403 |
| medium | T1201 | mapped_without_public_EVTX_validation | 1, 4104, 4661, 4688 |
| medium | T1202 | mapped_without_public_EVTX_validation | 1, 7, 13, 4104, 4624, 4648, 4657, 4688 |
| medium | T1204 | mapped_without_public_EVTX_validation | 1, 11, 12, 13, 14, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4657, 4688 |
| medium | T1207 | mapped_without_public_EVTX_validation | 4741, 4742, 4743, 5136 |
| medium | T1210 | mapped_without_public_EVTX_validation | 1, 6, 8, 22, 50, 56, 4625, 4688, 5723, 5805 |
| medium | T1218 | mapped_without_public_EVTX_validation | 1, 3, 7, 10, 11, 12, 13, 14, 29, 1040, 1042, 4103, 4104, 4624, 4648, 4657, 4688, 5156 |
| medium | T1218.004 | mapped_without_public_EVTX_validation | 1, 4688 |
| medium | T1218.005 | mapped_without_public_EVTX_validation | 1, 8, 4688 |
| medium | T1218.007 | mapped_without_public_EVTX_validation | 1, 3, 1040, 1042, 4104, 4688, 5156 |
| medium | T1218.010 | mapped_without_public_EVTX_validation | 1, 3, 7, 11, 22, 4688, 5156 |
| medium | T1218.011 | mapped_without_public_EVTX_validation | 1, 3, 7, 8, 11, 13, 4624, 4648, 4657, 4688, 5156 |
| medium | T1220 | mapped_without_public_EVTX_validation | 1, 7, 4688 |
| medium | T1482 | mapped_without_public_EVTX_validation | 1, 5, 11, 18, 22, 30, 4103, 4104, 4662, 4688, 4689 |
| medium | T1486 | mapped_without_public_EVTX_validation | 1, 7, 11, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4656, 4663, 4688, 5145 |
| medium | T1505.001 | mapped_without_public_EVTX_validation | 11 |
| medium | T1505.003 | mapped_without_public_EVTX_validation | 1, 11, 365, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116, 4688 |
| medium | T1543.003 | mapped_without_public_EVTX_validation | 1, 6, 11, 12, 13, 14, 4624, 4648, 4657, 4674, 4688, 4697, 4698, 7036, 7045 |
| medium | T1546 | mapped_without_public_EVTX_validation | 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 21, 32, 57, 60, 70, 92, 115, 125, 149, 167, 174, 177, 202, 208, 232, 4104, 4625, 4657, 4688, 5860, 5861, 8128 |
| medium | T1546.003 | mapped_without_public_EVTX_validation | 1, 7, 10, 11, 19, 20, 21, 2012, 4104, 4624, 4662, 4688, 5859, 5861 |
| medium | T1546.008 | mapped_without_public_EVTX_validation | 1, 12, 13, 14, 4657, 4688 |
| medium | T1546.011 | mapped_without_public_EVTX_validation | 1, 11, 13, 4657, 4688 |
| medium | T1546.015 | mapped_without_public_EVTX_validation | 1, 13, 4104, 4657, 4688 |
| medium | T1547.001 | mapped_without_public_EVTX_validation | 1, 11, 12, 13, 14, 4657, 4688 |
| medium | T1547.002 | mapped_without_public_EVTX_validation | 1, 4688 |
| medium | T1548.002 | mapped_without_public_EVTX_validation | 1, 7, 10, 11, 12, 13, 14, 4104, 4657, 4688 |
| medium | T1550 | mapped_without_public_EVTX_validation | 2, 3, 4104, 4624, 4625, 4648, 4656, 4672, 4768, 4769, 4964, 5145 |
| medium | T1550.002 | mapped_without_public_EVTX_validation | 2, 3, 4104, 4624, 4625, 4648, 4776, 6038, 6039, 8002 |
| medium | T1552.001 | mapped_without_public_EVTX_validation | 1, 11, 4104, 4688 |
| medium | T1553.003 | mapped_without_public_EVTX_validation | 13, 4657 |
| medium | T1555 | mapped_without_public_EVTX_validation | 1, 3, 11, 4104, 4624, 4625, 4648, 4663, 4688, 5145, 5379, 5382 |
| medium | T1555.003 | mapped_without_public_EVTX_validation | 1, 4104, 4624, 4663, 4688 |
| medium | T1555.004 | mapped_without_public_EVTX_validation | 1, 3, 4624, 4625, 4648, 4688, 5379, 5382 |
| medium | T1555.005 | mapped_without_public_EVTX_validation | 8 |
| medium | T1556 | mapped_without_public_EVTX_validation | 3, 13, 4624, 4657, 4776, 5136 |
| medium | T1557 | mapped_without_public_EVTX_validation | 1, 2, 11, 22, 4100, 4104, 4624, 4625, 4648, 4662, 4688, 4697, 5136, 5137, 5145 |
| medium | T1558.001 | mapped_without_public_EVTX_validation | 4768 |
| medium | T1558.002 | mapped_without_public_EVTX_validation | 4624 |
| medium | T1558.003 | mapped_without_public_EVTX_validation | 1, 5, 16, 27, 35, 36, 37, 38, 4104, 4611, 4624, 4648, 4673, 4688, 4768, 4769, 5136, 5156, 14674, 16990, 16991 |
| medium | T1558.004 | mapped_without_public_EVTX_validation | 4624, 4648, 4738, 4768, 4769 |
| medium | T1560.001 | mapped_without_public_EVTX_validation | 1, 4688 |
| medium | T1562.001 | mapped_without_public_EVTX_validation | 1, 4, 12, 13, 16, 255, 600, 4104, 4657, 4660, 4688, 5001, 5010, 5012, 5101, 7036 |
| medium | T1562.002 | mapped_without_public_EVTX_validation | 1, 10, 13, 4657, 4688, 4719, 7040 |
| medium | T1562.004 | mapped_without_public_EVTX_validation | 1, 11, 13, 2004, 2071, 2097, 4104, 4657, 4688 |
| medium | T1564.002 | mapped_without_public_EVTX_validation | 1, 12, 13, 14, 4657, 4688 |
| medium | T1572 | mapped_without_public_EVTX_validation | 1, 3, 22, 4104, 4688, 5156 |
| medium | T1574 | mapped_without_public_EVTX_validation | 1, 7, 11, 13, 23, 26, 4657, 4688 |
| medium | T1574.011 | mapped_without_public_EVTX_validation | 1, 4104, 4663, 4688 |
| medium | T1574.012 | mapped_without_public_EVTX_validation | 13, 4104, 4657 |
| medium | T1649 | mapped_without_public_EVTX_validation | 1, 3, 70, 1007, 4624, 4625, 4648, 4662, 4672, 4688, 4741, 4768, 4886, 4887, 4964, 5156 |

## Source status

- elastic (optional, present): repo_cache/elastic-detection-rules; files scanned: 494; Windows references: 486
- hayabusa (optional, present): repo_cache/hayabusa-rules; files scanned: 4983; Windows references: 4308
- sigma (optional, present): repo_cache/sigma; files scanned: 2410; Windows references: 2166

## Guardrails

- Third-party rule references are research evidence only; they never create a mapped, telemetry-supported, or validated engine state.
- No upstream rule content is copied into this report. Source licenses, provenance, and update policies remain the responsibility of the rule-source owner.
- Parsing is conservative text extraction for local YAML, TOML, and text files; nested structures and semantic rule logic are not evaluated.
- Strict mode fails only for paths supplied through --required-source. Missing optional --source mirrors and engine-coverage files are reported but do not fail the audit.
