# Secure File Transfer Monitoring System - Final Audit Report
_Generated: 2026-10-11 09:13:06_

## 1. Executive Summary
- Total file events logged: **210**
- Events involving sensitive files: **6**
- Alerts raised: **8**
- Integrity checks: **8** (6 match, **2 mismatch**)

## 2. Activity by Event Type
| Event | Count |
|---|---|
| BULK_TRANSFER | 1 |
| COPY | 6 |
| CREATE | 200 |
| DELETE | 1 |
| MODIFY | 1 |
| MOVE | 1 |

## 3. Alerts by Severity
| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 5 |
| WARNING | 1 |

## 4. Alerts by Type
| Alert type | Count |
|---|---|
| INTEGRITY_FAILURE | 2 |
| SENSITIVE_TO_USB | 1 |
| SENSITIVE_TO_CLOUD | 1 |
| UNAUTHORIZED_MOVEMENT | 1 |
| SUSPICIOUS_OUTBOUND | 1 |
| SUSPICIOUS_BULK_TRANSFER | 1 |
| SENSITIVE_DELETED | 1 |

## 5. Activity by User
| User | Events |
|---|---|
| bob | 201 |
| alice | 4 |
| intern01 | 2 |
| admin | 1 |
| SYSTEM | 1 |
| root | 1 |

## 6. Alert Details
| Time | Severity | Type | Message | User |
|---|---|---|---|---|
| 2026-10-11 09:12:51 | CRITICAL | SENSITIVE_TO_USB | Sensitive file copied to USB drive: salary_2026.csv -> /home/student/sftms_demo/USB_E/salary_2026.csv | intern01 |
| 2026-10-11 09:12:53 | CRITICAL | SENSITIVE_TO_CLOUD | Sensitive file copied to cloud-sync folder: /home/student/sftms_demo/CloudSync/Dropbox/server_private.key | bob |
| 2026-10-11 09:12:54 | HIGH | UNAUTHORIZED_MOVEMENT | Sensitive file moved to unapproved location: /home/student/sftms_demo/Staging/customer_db.sql | admin |
| 2026-10-11 09:12:56 | HIGH | INTEGRITY_FAILURE | File hash mismatch detected: /home/student/sftms_demo/Documents/Confidential/server_private.key | SYSTEM |
| 2026-10-11 09:12:57 | HIGH | INTEGRITY_FAILURE | File hash mismatch detected after copy: /home/student/sftms_demo/Documents/Public/report.docx | alice |
| 2026-10-11 09:12:59 | WARNING | SUSPICIOUS_OUTBOUND | Outbound transfer to removable location: /home/student/sftms_demo/USB_E/budget_draft.txt | alice |
| 2026-10-11 09:13:01 | HIGH | SUSPICIOUS_BULK_TRANSFER | 50 files transferred to unknown directory '/home/student/sftms_demo/Downloads/unknown_dir' within 60s | root |
| 2026-10-11 09:13:04 | HIGH | SENSITIVE_DELETED | Sensitive file deleted: /home/student/sftms_demo/Documents/Archive/customer_db.sql | intern01 |

## 7. Integrity Verification Results
| Time | File | Context | Pre-hash | Post-hash | Result |
|---|---|---|---|---|---|
| 2026-10-11 09:12:48 | notes.txt | copy from /home/student/sftms_demo/Docum | ee3f856dbf7a... | ee3f856dbf7a... | MATCH |
| 2026-10-11 09:12:50 | customer_db.sql | copy from /home/student/sftms_demo/Docum | 12893879a711... | 12893879a711... | MATCH |
| 2026-10-11 09:12:51 | salary_2026.csv | copy from /home/student/sftms_demo/Docum | 575d17d3490b... | 575d17d3490b... | MATCH |
| 2026-10-11 09:12:53 | server_private.key | copy from /home/student/sftms_demo/Docum | 02d9ca7f5984... | 02d9ca7f5984... | MATCH |
| 2026-10-11 09:12:54 | customer_db.sql | move from /home/student/sftms_demo/Docum | 12893879a711... | 12893879a711... | MATCH |
| 2026-10-11 09:12:56 | server_private.key | modification of sensitive file | 02d9ca7f5984... | 0807a9c12c49... | MISMATCH |
| 2026-10-11 09:12:57 | report.docx | copy from /home/student/sftms_demo/Docum | 051a581cbb26... | e40a6f697038... | MISMATCH |
| 2026-10-11 09:12:59 | budget_draft.txt | copy from /home/student/sftms_demo/Docum | c4e1c31cf00f... | c4e1c31cf00f... | MATCH |

## 8. Conclusion
Policy violations were detected and should be investigated by the security team.