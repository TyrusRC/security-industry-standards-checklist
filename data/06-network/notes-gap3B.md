# Notes gap batch B (Windows and Active Directory)

Tests: 9 ADCS, 12 AD, 14 WIN, 3 WRMT = 38. Files: gap3-adcs.yaml, gap3-ad.yaml, gap3-win.yaml, gap3-wrmt.yaml.

Fetched into sources/extra/gap3-B/ (by this run, with curl, from learn.microsoft.com): mdi-accounts-posture.md, kerberos-constrained-delegation-overview.md, app-control-script-enforcement.md, app-control-overview.md, powershell-app-control.md. The other files in that folder were already there. The Azure Windows baseline page (guest-configuration-baseline-windows.md) replaced the xlsx for setting values (rows and CCE ids).

## B1 NTLM relay: NET-WIN-001 (SMB signing), -002 (LDAP signing, clear-text binds), -003 (NTLMv1/LM). EPA on HTTP is in NET-ADCS-007 (ESC8) only. No generic EPA test: no source for other HTTP endpoints. LDAP channel binding registry value is not in the sources read: the test uses events 3039-3041 and the policy name only.
## B2 AD CS: NET-ADCS-001..009 (ESC1, ESC2/15, ESC3, ESC4, ESC6, ESC7, ESC8, ESC11, auditing). Sources: certificates.md, secure-delegate-audit-certification-authority.md.
## B3 NET-AD-001, -002, -012. B4 NET-AD-005, -006, -007. B6 NET-AD-003, -004. B7 NET-AD-008, -009. B8 NET-AD-010, -011 (DCSync rights, WriteDACL on groups, AdminSDHolder; source: mdi-accounts-posture.md). Not covered: GPO write rights (no page read).
## B5 NET-WIN-004 (LSA protection), -005 (Credential Guard), -006 (WDigest), -007 (cached logons). Remote Credential Guard is a policy row in NET-WRMT-002. CAPEC-645 cited in -004/-005.
## B9 NET-WRMT-001 (WinRM), -002 (RDP), -003 (deny network logon). Skipped: remote UAC token filtering (LocalAccountTokenFilterPolicy). No source read contains it.
## B10 NET-WIN-008 (App Control/AppLocker), -009 (PowerShell logging, CLM). Used NIST CM-7(2)/(5) from the 800-53 catalog.
## B11 NET-WIN-010 (AlwaysInstallElevated), -011 (service binary/key ACL, unquoted paths), -012 (autorun/task targets), -013 (user rights), -014 (UAC). -011 and -012 rest on CWE only (thin source), as the plan says. SeImpersonate service review rests on the baseline row only.
## Other points
- Defender for Identity ESC pages say some assessments need a sensor on the AD CS server. Tests give direct read steps (certutil, Get-ADObject) as hints; the exact flag bit values are not quoted from the sources.
- The baseline lists "Disallow Digest authentication = 0" for WinRM (value as printed in the source). The test names the setting, not the value.
- Commands in `example` are hints written by the author; the sources give the settings, not all command lines.
