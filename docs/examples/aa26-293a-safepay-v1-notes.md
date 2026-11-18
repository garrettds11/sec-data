# SafePay AA26-293A — scenario v1

## Inputs and provenance

- Scenario: `scenarios/cisa/aa26-293a-safepay-v1.json`, ID `cisa-aa26-293a-safepay-composite-v1`, short output label `safepay-v1`.
- [CISA advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a), **#StopRansomware: SafePay Ransomware**, initial publication **October 20, 2026**, 19 pages. Official co-author [FBI/IC3 PDF](https://www.ic3.gov/CSA/2026/261020.pdf) was downloaded and reviewed in full on November 18, 2026. Its SHA-256 is recorded in the catalog. Authors: FBI, CISA, USSS, Germany's Landeskriminalamt Rheinland-Pfalz, UK's NCA and North West Regional Organised Crime Unit.
- [Original STIX JSON URL](https://www.cisa.gov/sites/default/files/2026-10/AA26-293A-stix.json) returned HTTP 403 from the authoring environment. The user supplied the original attachment. The scenario uses that uploaded JSON, not the third-party copy found during discovery.
- The exact uploaded bytes are retained at [`catalogs/intelligence/sources/AA26-293A-stix.json`](../../catalogs/intelligence/sources/AA26-293A-stix.json), with text normalization disabled for that path. **38,394 bytes**, SHA-256 **`73cbd07da8d74a322aa0c76a08933c8731045590e8abdee3409639f7ef40f5d0`**, STIX 2.1, bundle **`bundle--4be1cbd1-727b-4ed9-9c0f-61ed46ca27f5`**.
- Machine-readable source inventory and verification input: [`aa26-293a-safepay-coverage-v1.json`](../../catalogs/intelligence/aa26-293a-safepay-coverage-v1.json). Only the scenario JSON is a generation input. The source STIX and catalog stay outside the analyst index.

## What the STIX actually contains

| Object type | Count | Treatment |
| --- | ---: | --- |
| Indicator | 19 | All indicator patterns inventoried and all constituent values represented |
| Attack pattern | 23 | Preserve source objects; map selected observable behaviors below, document omissions |
| Malware | 12 | Tool names retained; a STIX malware label does not override the advisory's legitimate-tool qualifications |
| Vulnerability | 5 | All CVEs retained in catalog/notes; exploitation is not fabricated for unsupported products |
| Report | 1 | Preserve source metadata and reference graph |
| Marking definition | 1 | Preserve source marking; do not silently invent referenced marking definitions |
| Location | 1 | Retain context; does not establish location of every connection |
| Relationship | 1 | Preserve source relationship; do not infer unsupported additional links |
| **Total** | **63** | **Not 63 indicators** |

The 19 indicator objects contain **22 distinct atomic values**: **9 IPv4**, **5 SHA-1**, **6 SHA-256**, **1 MD5**, **1 SSDEEP**. Eighteen indicators have one equality term; one SharpShares indicator is an **OR** across SHA-1, SHA-256, MD5 and SSDEEP. Coverage requires all four alternatives independently to ensure none is silently omitted; this is stronger than one OR indicator match. The checker is not a general STIX parser/evaluator or a fuzzy-similarity engine. It verifies metadata equality in generated fields.

The uploaded source has references to a creator identity, another marking object and an extension definition that are absent from its object list. The catalog records these unresolved references and the complete original snapshot retains them unchanged. No creator/marking content is invented. No indicator is marked revoked; no `valid_until` is supplied.

### Reconciliation with the publication

| Source | Values | Representation and qualifications |
| --- | --- | --- |
| STIX IPv4 patterns / PDF Table 2, p.8 | Same 9 IPs | `dest` in independent historical network observations; CISA describes intrusion, hosting, panel, exfiltration and `soc.dll` C2 roles. Shared infrastructure and historical use do not prove present maliciousness. Synthetic direction/443 choices do not establish those roles. |
| PDF Table 4, p.10 | 4 SHA-1 values | All in STIX and `file_hash` |
| PDF Table 5, pp.10–11 | 6 SHA-256 values | All in STIX and `file_hash`; SharpShares also appears as `process_hash` in the main chain |
| STIX-only SharpShares OR alternatives | Additional SHA-1, MD5, SSDEEP | All retained in independent file-metadata observations; SSDEEP uses `file_hash_ssdeep` and case-sensitive exact comparison |
| PDF Table 3, pp.8–10 | 30 source rows, 36 split filename/pattern alternatives | All represented in `file_path`; slash alternatives split, wildcard values get explicitly fictional representatives; shared names are weak/context-dependent matching leads |
| PDF p.11 hostname list | 4 hostnames, absent from the indicator patterns | `src` in independent failed-logon fixtures. No DNS lookup or published IP-to-hostname relationship is invented. |

The catalog contains **62 value assertions**: 22 STIX values, 36 filename alternatives and 4 hostnames. All source indicator IDs, raw patterns, dates, normalization and per-value mappings are retained. The standalone `*.dll` pattern is extremely broad and should never be treated as a high-confidence detection.

The STIX describes one locker hash as `Lockbit 3.0`; the publication associates that same digest with `locker.dll`. The source wording is preserved; this exercise does not resolve malware lineage. The STIX report's `published` is **October 15, 2026**, while the PDF's publication date is **October 20, 2026**. These are separate source metadata values, not corrected incident dates. CTI created/modified/valid-from times can precede publication or the reported November 2024–August 2026 observation interval. None automatically determines the synthetic event timeline.

## Ordered adaptation and evidence limits

The first ten steps form one fictional compromise; the last four are independent historical matching fixtures. Their placement in the same output supports lookup tests without claiming every IOC appeared together in one victim.

| Offset | Step | Source basis / synthetic assumptions |
| --- | --- | --- |
| +1 min | Failed then successful RDP access | pp.4–5, credential abuse/RDP. Fictional stolen `LAB\admin` credentials and `prod-rdp-01`; the IP is not asserted to be a Mullvad exit. |
| +5 min | Existing-account manipulation | p.5, T1098. Invented command/change evidence; account state is not enforced. |
| +10 min | ShareFinder, SharpShares, nltest | pp.5,7–10. Invented arguments/placement; launches do not prove enumeration succeeded. |
| +20 min | SMB/PsExec remote execution evidence | pp.5–7, T1021.002/T1569.002. Uses existing Windows RDP/file assets and an already-privileged account. Process parent and remote ordering are fictional. |
| +30 min | Security registry change | p.5/Table 11, T1685. Registry write alone does not prove security impairment; continuing Sysmon evidence does not claim a stopped sensor. |
| +40 min | File read and WinRAR archive | pp.5–7, T1560.001. Fictional source file/archive; read and process evidence do not prove which bytes were uploaded. |
| +50 min | Rclone process and outbound transfer | pp.5,7/Table 2, T1048. Fictional config, port and bytes; no cloud-provider/DNS binding invented. |
| +60 min | VSS-stop command | p.6, T1490. Launch only, no service-stop success claim. |
| +70 min | Ransomware fingerprint and `.SafePay` rename | p.6/Tables 4–5, T1486. File/process metadata only; no malware bytes or cryptographic operation. |
| +75 min | Executable deletion | p.6, T1070.004. Synthetic observation of possible cleanup. |
| +80 min | All nine historical IPs | Independent historical coverage, not extra causally linked C2/exfiltration. |
| +81 min | All thirteen hash values | Independent fingerprints, including every SharpShares alternative. Generic RunPE/injected filenames are fictional, not source filenames. |
| +82 min | Publication filename alternatives | Independent file metadata; legitimate tools and benign outputs remain qualified leads. |
| +83 min | Publication hostnames | Failed-logon fixtures using names only, not additional managed assets. |

### Inventory and omitted behaviors

Reuse the repository's Windows `prod-rdp-01`, `prod-file-01` and existing `LAB\admin` identity. Compromise of that privileged identity is a fictional prerequisite, not something inferred from a successful low-privilege logon. The internal SMB listener already exists in inventory. The JSON does not install tools, configure a VPN, create internal hosts, or enforce permissions.

Source CVEs are **CVE-2020-3259**, **CVE-2023-20269**, **CVE-2023-27532**, **CVE-2024-40711**, **CVE-2024-40766**. Their CWE qualifications are retained in the official publication; this branch chooses credential-based access and does not invent ASA/FTD, Veeam or SonicWall assets, exploit requests, findings or successful exploitation. Phishing, VPN session mechanics, Mullvad attribution, automated CVE exploitation (T1190), UAC COM bypass (T1548.002), token impersonation (T1134.001), packing (T1027.002), binary proxy execution (T1218), new-account creation, successful DCSync/Mimikatz credential extraction, actual WinRM/remote-tool installations, OneDrive/Backblaze service sessions (T1567), NAS factory reset, ransom-note content, phone extortion, Tor conversation, cryptocurrency payment and cryptographic encryption are **not simulated**. Relevant tool filenames may still appear as historical metadata; that does not establish execution or efficacy.

All 23 ATT&CK source objects and twelve tool-labeled objects are preserved in the catalog, including unselected alternatives. The source's questionable Mimikatz/collection mapping is not silently replaced with an invented technique mapping. Table 1 also names tools beyond the STIX malware objects; they are reviewed in the publication. FileZilla, Mimikatz, ScreenConnect, 7-Zip, WinRM, TeamViewer, Acronis, NetExec and Backblaze are alternatives/context, not all added as executed steps. Dual-use tools are not inherently malicious. Incident response recommendations do not imply synthetic successful containment; no containment outcome is planted.

## Proposed run settings and commands

These are **synthetic exercise settings**, not CISA's incident start, duration or affected-host count:

| Setting | Proposed value | Reason |
| --- | --- | --- |
| Seed | 2 | Reviewed repeatable details |
| Start | `2026-10-21T08:00:00Z` | Arbitrary exercise time after publication; does not assert an actual incident on that day |
| Duration | 120 minutes | Contains fixed offsets ending at +83 minutes; minimum accepted whole-minute duration is 84 |
| Inventory | 23 hosts | Existing repository inventory supporting named assets; not 23 affected victims |
| Total | 10,000 events | 85 prescribed + 9,915 routine if generated with these settings |
| Output | `output/safepay-v1-runNNN` | Allocated automatically from the scenario's `output_name` |

From the extracted repository folder with the README's Python environment prepared:

```powershell
$python = '.\.venv\Scripts\python.exe'
$scenarioFile = '.\scenarios\cisa\aa26-293a-safepay-v1.json'
$coverageFile = '.\catalogs\intelligence\aa26-293a-safepay-coverage-v1.json'
$seed = 2
$startTime = '2026-10-21T08:00:00Z'
$durationMinutes = 120
$targetEvents = 10000
$hostCount = 23

& $python .\validate_scenario.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount --duration-minutes $durationMinutes `
    --target-events $targetEvents
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed.' }

$runJson = & $python .\create_dataset.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount --start-time $startTime `
    --duration-minutes $durationMinutes --target-events $targetEvents --json
if ($LASTEXITCODE -ne 0) { throw 'Generation failed.' }
$outputDir = ($runJson | ConvertFrom-Json).output_dir

& $python .\validate_ioc_coverage.py --dataset-dir $outputDir `
    --coverage-file $coverageFile `
    --output (Join-Path $outputDir 'ioc-coverage-report.json')
if ($LASTEXITCODE -ne 0) { throw 'Indicator coverage failed.' }
Write-Host $outputDir
```

For Splunk lookup matching, use IP `src`/`dest`, hostnames in `src`, cryptographic hashes in `file_hash`/`process_hash`, filename patterns in `file_path`, and SSDEEP in `file_hash_ssdeep`. SSDEEP equality is case-sensitive.

A generated run should report **62 assertions present, zero missing**. Check the manifest's event count before ingest. Index only `events/*.jsonl` using `secdata:cim:json`; source snapshots, the catalog, context, truth and reports remain outside the analyst index. Search All Time.

## Validation status

Structural validation at the proposed settings reports **14 steps, 85 prescribed observations, minimum 84 minutes**, `dataset_generated: false`. Tests compile the authored observations in memory and check every coverage assertion, source hash and indicator mapping; removing evidence must produce missing assertions. That is separate from exporting a new user dataset, ingesting into Splunk or testing a detection. No live indicator connections, malware execution, AWS upload or Splunk ingestion is performed. Review the proposed chain/settings before generating the exercise.
