# AA24-131A Black Basta scenario proposal

## Status

One runtime input is supplied: aa24-131a-black-basta.json (schema version 1). The 23 ordered steps contain 43 prescribed observations. This is a proposal for review. The original proposal was authored without generating a dataset or performing network activity. Repository example checks subsequently export temporary test packages as described below.

The narrative is an authored composite of activities reported across Black Basta affiliates, not a reconstruction of a single documented victim. Source facts and fictional assumptions are labeled separately in every step description. These descriptions remain private truth metadata during a future run.

## Sources and contract

Source S1: Joint Cybersecurity Advisory AA24-131A, #StopRansomware: Black Basta, original publication May 10, 2024; reviewed revision November 8, 2024. Authors: FBI, CISA, HHS and MS-ISAC. Printed page references below refer to the 10-page November revision.

- Official partner PDF: https://www.ic3.gov/CSA/2024/240511.pdf
- CISA landing page: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
- CISA revision: https://www.cisa.gov/sites/default/files/2024-11/aa24-131a-joint-csa-stopransomware-black-basta_3.pdf
- Direct CISA retrieval returned HTTP 403; the official IC3 copy supplied the reviewed text.

Reviewed sec-data main commit: 9eb63baec2b74d57291b35dcc6cd67022f2905d1.

- Contract: https://github.com/garrettds11/sec-data/blob/9eb63baec2b74d57291b35dcc6cd67022f2905d1/docs/scenarios.md
- Compiler: https://github.com/garrettds11/sec-data/blob/9eb63baec2b74d57291b35dcc6cd67022f2905d1/common/scenario.py
- Runtime: https://github.com/garrettds11/sec-data/blob/9eb63baec2b74d57291b35dcc6cd67022f2905d1/create_dataset.py

The scenario uses only existing supported keys. Structured facts, citations, techniques and IOC registry keys cannot be added to this schema. Provenance and assumptions therefore reside in private descriptions and this companion explanation. Analyst observations do not contain story or maliciousness labels. The runtime later writes the descriptions and dependencies to truth/scenario-truth.json.

## Story and proposed run settings

After a spam-related fake-support pretext, an operator accepts remote assistance on a Windows RDP host. Discovery and credential-access activity precede use of a privileged account on other systems. A file server reads business documents, launches Rclone and connects to a historical exfiltration indicator. Later observations show recovery-inhibition attempts, a fictional encryptor process, .basta artifacts and readme.txt. A final fictional response blocks one later outbound retry.

| Setting | Proposal for approval |
| --- | --- |
| Seed | 42 |
| Start | 2024-11-12T08:00:00Z, a fictional historical exercise date after all listed IOC first-seen dates |
| Duration | 120 minutes |
| Hosts | 23 default assets |
| Total events | 10,000: 43 prescribed observations plus 9,957 ordinary events |
| Background weights | web 5, file 3, egress 3, ingress 1; session weights, not event percentages |
| Future output | output/aa24-131a-run-01, a new directory |

Offsets are fixed and do not stretch when duration increases. Minimum whole-minute duration is 111, because the last step occurs at second 6600. Seed changes affect context details and ordinary activity, not the prescribed plot or literal indicator values.

## Fictional environment and assumptions

prod-rdp-01 is an interactive Windows Server/RDP host, not a newly invented employee workstation or public ScreenConnect appliance. prod-file-01 is the primary collection/transfer/artifact host; prod-file-02 provides the benign backup comparison and a later RDP logon. dc-01 receives a contextual scanner finding and privileged SMB authentication.

LAB\\operator accepts remote assistance and is assumed to have local administrator rights on the entry host. Successful credential recovery after the Mimikatz process is an explicit author assumption; later LAB\\admin use does not prove how credentials were obtained. LAB\\svc_backup performs the benign comparison. NT AUTHORITY\\SYSTEM is the standard local service identity for the PsExec service, not an added domain account.

Seed 42 yields Windows Server 2019 on dc-01/prod-rdp-01 and Windows Server 2022 on both file hosts. Installed tools, elevated consent, audit coverage, file permissions, paths, process ancestry, timings and response actions are fictional. The compiler does not install tools or enforce these privileges.

## Ordered steps for review

| # | Offset | Step ID | Evidence and source grounding |
| --- | --- | --- | --- |
| 1 | 01:00 | context-printnightmare-finding | S1 p.3 names CVE-2021-34527. Fictional dc-01 scanner finding; no exploitation is asserted. |
| 2 | 02:00 | benign-rclone-backup-control | Fictional approved Rclone backup by svc_backup to the repo's authorized backup provider. |
| 3 | 05:00 | remote-support-execution | S1 pp.2–4: fake support and AnyDesk. Email bombing/Teams contact remain narrative; an authored process and relay flow are visible. |
| 4 | 07:00 | historical-domain-lookups | Both Table 8 domains appear in DNS queries. NXDOMAIN answers are invented; no domain-to-IP association is claimed. |
| 5 | 08:00 | primary-c2-indicator-contact | Authored TCP/443 flow to historical IOC 170.130.165.73. |
| 6 | 15:00 | softperfect-network-discovery | S1 pp.3–4: netscan.exe. Five authored flows target inventory-declared services on three hosts. |
| 7 | 18:00 | masqueraded-discovery-utility | S1 p.3: Intel/Dell-like naming. Intel.exe basename, path suffix and parentage are authored. |
| 8 | 20:00 | secondary-c2-indicator-contact | Authored flow to historical IOC 45.11.181.44; not evidence of a common historical operation. |
| 9 | 25:00 | credential-access-process | S1 pp.3–4: Mimikatz. Process only; credential recovery and effective privileges are not observed. |
| 10 | 30:00 | privileged-account-use | S1 pp.2–3: valid accounts. Invented admin SMB authentication to dc-01. |
| 11 | 35:00 | psexec-lateral-execution | S1 pp.3–4: PsExec. Authored SMB, authentication and service/process observations on prod-file-01. |
| 12 | 40:00 | rdp-lateral-session | S1 p.3: RDP. Invented admin session to prod-file-02. |
| 13 | 45:00 | file-host-c2-indicator-contact | Authored flow to historical IOC 79.132.130.211. Does not prove Cobalt Strike protocol. |
| 14 | 50:00 | powershell-defense-impairment-attempt | S1 pp.3,5–6. Invented script path; no script body or antivirus state. |
| 15 | 52:00 | backstab-defense-impairment-attempt | S1 pp.3,5. Process only; successful EDR shutdown is not asserted and telemetry continues. |
| 16 | 60:00 | sensitive-file-reads | S1 reports theft; the three filenames, paths and read events are fictional. No real PHI or contents. |
| 17 | 65:00 | rclone-transfer-process | S1 pp.3–4. Invented Rclone command and remote configuration name. |
| 18 | 66:00 | historical-exfiltration-indicator-flow | Historical IOC 66.42.118.54. Two authored sensor views of one flow; not two separate transfers. |
| 19 | 75:00 | shadow-copy-deletion-attempt | S1 pp.3,6: vssadmin. Authored command string; deletion success unknown. |
| 20 | 80:00 | encryptor-delivery-and-launch | Authored wup.exe filename and delivery; not a published file IOC or actual executable. |
| 21 | 82:00 | basta-extension-artifacts | S1 p.3: .basta suffixes. Filepath observations do not prove encryption. |
| 22 | 84:00 | ransom-note-artifact | S1 pp.2–3: readme.txt. File creation only, without contents or contact/payment activity. |
| 23 | 110:00 | fictional-containment-and-blocked-retry | Entirely fictional response extension. One later blocked flow, not proof of complete containment or recovery. |

## Published IOC coverage

All six network indicators in the November revision are represented. Defanged display forms are below; JSON fields use normal syntax for offline matching.

| IOC | First seen in source | Source description | Scenario use |
| --- | --- | --- | --- |
| 170.130.165[.]73 | 2024-10-14 | Likely Cobalt Strike infrastructure | bb-c2-primary network flow |
| 45.11.181[.]44 | 2024-10-24 | Likely Cobalt Strike infrastructure | bb-c2-secondary network flow |
| 66.42.118[.]54 | 2024-10-15 | Exfiltration server | bb-exfil outbound flow and later blocked retry |
| 79.132.130[.]211 | 2024-10-24 | Likely Cobalt Strike infrastructure | bb-c2-filehost network flow |
| Moereng[.]com | 2024-10-09 | Suspected Black Basta Cobalt Strike domain | moereng.com DNS query |
| Exckicks[.]com | 2024-10-02 | Suspected Black Basta Cobalt Strike domain | exckicks.com DNS query |

Sources: S1 Table 7, p.6; Table 8, p.7. No live indicator connections or lookups were performed. The original IPs are retained for offline IOC matching. Their example.net entity labels are fictional, not observed DNS names. No domain is assigned to a published IP. Source qualifications such as likely and suspected remain relevant.

The November update removed outdated indicators from its initial release. Superseded hashes/IPs were not silently mixed into the newer set. These are historical training indicators, not claims of present maliciousness or ownership.

## Technique coverage

| Source ATT&CK identifier | Selected treatment |
| --- | --- |
| T1566, Phishing | Source context; no separate attachment infection added. |
| T1566.004, Spearphishing Voice | Fake-support narrative prerequisite; no native call/Teams evidence. |
| T1204, User Execution | AnyDesk launch observed; user persuasion and consent are assumed. |
| T1190, Exploit Public-Facing Application | ScreenConnect alternative retained as context, not selected. |
| T1078, Valid Accounts | Later admin use after an explicitly assumed credential-access outcome; p.2 prose. |
| T1036, Masquerading | Invented Intel.exe representation of documented naming. |
| T1068, Exploitation for Privilege Escalation | Source technique catalog only; no successful CVE exploitation planted. Mimikatz launch is not proof of exploitation. |
| T1059.001, PowerShell | Process observation with an invented script path. |
| T1562.001, Impair Defenses | Attempt intent in truth; no effective AV/EDR state change. |
| T1490, Inhibit System Recovery | vssadmin process; deletion outcome unknown. |
| T1486, Data Encrypted for Impact | Payload/artifact approximation, not actual cryptographic proof. |

These identifiers follow S1 pp.2–6. RDP, PsExec, scanning and exfiltration are also modeled as documented behaviors; additional ATT&CK IDs are not attributed to the source.

## Software coverage

| Software/artifact named in S1 | Treatment |
| --- | --- |
| AnyDesk | Selected remote-support process plus fictional relay flow. |
| Microsoft Teams | Narrative pretext only. |
| Microsoft Quick Assist | Documented alternative, not also forced into the same entry chain. |
| Qakbot | Documented alternative initial access/delivery; absent from selected branch. |
| SoftPerfect / netscan.exe | Process and service probes. |
| Intel / Dell utility names | Intel.exe represented; Dell naming retained as source context. Paths and binary identity are not source IOCs. |
| Mimikatz | Process only; no secrets or tool output. |
| PsExec / RDP | Process, network and authentication observations. |
| Cobalt Strike | Historical indicator correlation only; no payload/configuration/beacon reconstruction. |
| PowerShell / Backstab | Process observations without successful defense impairment. |
| Rclone | Suspicious transfer correlation plus a benign comparison. |
| vssadmin.exe | Authored process/command-line observation only. |
| Black Basta encryptor | Fictional wup.exe metadata; no executable or published hash. |
| .basta / readme.txt | Filepath artifacts only. |
| BITSAdmin / ScreenConnect / Splashtop / WinSCP | Documented alternatives, not included as additional required stages. |
| ChaCha20 / RSA-4096 | Source-described algorithms retained in private narrative; not implemented or established by event fields. |
| Basta News / onion contact | Extortion context only; no leak, payment or actual connection. |

Tool use is documented in S1 pp.3–5. The legitimate tools listed here are not inherently malicious. The single selected story intentionally does not combine every alternative tool or exploit path.

## Weakness coverage

| Weakness in S1 pp.2–3 | Source CWE | Proposal treatment |
| --- | --- | --- |
| ScreenConnect CVE-2024-1709 | CWE-288 | Alternate entry path, not selected; no public ScreenConnect service exists in the base model. |
| ZeroLogon CVE-2020-1472 | CWE-330 | Documented alternative; not emitted as exploitation. |
| NoPac CVE-2021-42278 | CWE-20 | Documented alternative; not emitted as exploitation. |
| NoPac CVE-2021-42287 | CWE-269 | Documented alternative; not emitted as exploitation. |
| PrintNightmare CVE-2021-34527 | CWE-269 | One fictional dc-01 finding; not exploited in the story. |

The finding's high severity is an authored assessment value, not a quoted CISA CVSS score. Lack of patching, remote-support control and phishing-resistant authentication are source-informed defensive concerns, not automatically observed configuration failures. Excessive local privileges and privileged credential availability in this story are explicitly fictional enabling assumptions. No invented compliance failures are emitted.

## Modeling limits

1. Email flooding, voice/Teams messages, tenant identity and user consent have no supported native source/dataset pair. They remain narrative prerequisites; a process launch does not prove them.
2. The schema can add external entities but not arbitrary internal hosts or identities. Existing server hosts/accounts are reused, and their OS/role constraints are retained.
3. Process records do not prove installed versions, local privileges, successful secret recovery, AV/EDR disabling or shadow-copy deletion. The runtime does not execute any command strings.
4. A CVE finding is not exploit evidence. No vulnerable protocol state machine, real exploit, automatic elevation or patch transition is modeled.
5. The current field allow-list has no process_hash/file_hash fields. Historical file hashes are not inserted into unrelated fields or invented.
6. session_id is assigned per step, not propagated as an authenticated session across steps. Host/user/time/process identifiers support correlation; depends_on is private story logic, not analyst evidence. Explicit parent PIDs refer to preceding same-host processes.
7. Network flows do not identify Cobalt Strike protocol or prove callbacks. Published domain/IP relationships are not inferred. The NXDOMAIN answers, ports and byte counts are fictional.
8. File reads, Rclone and a later TLS flow support a transfer hypothesis; they do not prove which bytes moved or the destination configured inside Rclone. The two network sensor records describe one flow and must not be summed as two transfers.
9. File extensions and ransom-note metadata do not prove encryption, algorithm choice, outage, patient impact or irrecoverability. There is no real malware, PHI, ransom demand or payment.
10. The final blocked retry does not model effective rule deployment, eradication or restoration. It occurs after the earlier transfer/artifacts.
11. Tailored mode does not automatically emit the fixed reference story's compliance state, access-policy timelines, expected alerts or case outcomes. Detection evaluation requires separately authored searches and expected results.
12. The outputs are CIM-shaped synthetic observations, not exact native Microsoft/vendor raw logs. This single composite does not test all techniques, tools, CVEs or present-day Black Basta activity.

## Static validation

Validation passed with the actual repository load_scenario function and its field/reference helpers. A static walk checked the compiler constraints without calling compile_scenario or create_dataset.py. Only reference context was built in memory.

Checks covered JSON/schema keys, custom-entity conflicts, source/dataset support, required fields and value types, absence of reserved/truth event keys, reference resolution, chronological offsets and dependencies, delay/window bounds, byte totals, declared internal ports, unique host/process identifiers, earlier same-host parent PIDs and presence of all six IOCs.

End-to-end publication, Splunk ingest, CIM membership, detection effectiveness and high-volume performance were not tested. Static compatibility does not establish attack causality.

## Future command — not executed

After approving the sequence and settings, place the JSON under scenarios/cisa/ in your checkout and run from the repository root. The output directory must not already exist.

~~~powershell
$python = '.\.venv\Scripts\python.exe'
& $python .\create_dataset.py `
  --scenario-file .\scenarios\cisa\aa24-131a-black-basta.json `
  --seed 42 `
  --host-count 23 `
  --start-time '2024-11-12T08:00:00Z' `
  --duration-minutes 120 `
  --target-events 10000 `
  --output-dir .\output\aa24-131a-run-01
~~~

Only events/*.jsonl should later be ingested with sourcetype secdata:cim:json. Keep context/, truth/ and dataset-manifest.json outside the analyst event index. At least 43 total events are needed; 10,000 is a proposed exercise volume, not an already generated result.

## Investigation questions and evidence boundaries

- Which account/host first show remote-support activity? operator on prod-rdp-01; no native evidence of the spam/Teams exchange is available.
- Which historical indicators occur and on which hosts? All six are included; historical matching alone is not actor attribution.
- Why is the earlier Rclone use different? svc_backup, prod-file-02 and the authorized backup provider form the benign comparison.
- Is privilege escalation proven? No. A Mimikatz process and later admin use leave the credential acquisition bridge as an author assumption.
- Was PrintNightmare used? No exploit evidence is planted. The scanner finding is separate contextual risk.
- Was data exfiltrated? The visible sequence supports a hypothesis, not proof of exact content transfer.
- Were defenses disabled, backups deleted and files encrypted? Process/artifact indicators are present; successful state changes are not established.
- Did the final block prevent all damage? No. It shows one later blocked flow after earlier activity.


## Repository example validation

The companion input is now tracked at scenarios/cisa/aa24-131a-black-basta.json. Validate it with:

~~~powershell
.\.venv\Scripts\python.exe .\validate_scenario.py --scenario-file .\scenarios\cisa\aa24-131a-black-basta.json --seed 42 --host-count 23 --duration-minutes 120 --target-events 10000
~~~

The repository test suite validates all tracked scenario examples and exports this example into a temporary directory to reconcile prescribed/background counts and truth separation. These automated checks do not establish Splunk ingest or detection effectiveness, or approve an operational exercise. Earlier validation details above describe the original proposal; the shared validator replaces its one-off static check for new users.
