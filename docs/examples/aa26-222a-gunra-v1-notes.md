# Gunra AA26-222A — scenario v1

## Source and version

- Runnable JSON: [`scenarios/cisa/aa26-222a-gunra-v1.json`](../../scenarios/cisa/aa26-222a-gunra-v1.json), ID `cisa-aa26-222a-gunra-composite-v1`, short output name `gunra-v1`.
- [CISA advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a): **#StopRansomware: Gunra Ransomware**, initial publication **August 10, 2026**. CISA's page returned HTTP 403 during review. The full official co-author [FBI/IC3 PDF](https://www.ic3.gov/CSA/2026/260810.pdf), 21 pages, was downloaded and reviewed on November 18, 2026. Authors: FBI, CISA, DC3, NSA, USSS and Republic of Korea's National Police Agency. The source PDF's SHA-256 is in the coverage catalog.
- The user supplied the original [STIX JSON attachment](https://www.cisa.gov/sites/default/files/2026-08/AA26-222A-stix.json). The exact bytes are retained at [`catalogs/intelligence/sources/AA26-222A-stix.json`](../../catalogs/intelligence/sources/AA26-222A-stix.json), with Git text normalization disabled for that file: **62,466 bytes**, SHA-256 **`b699465192e59d8cbd15ffe9da0b7997118c16c881f42ddcd2dbe5941d1eaede`**, bundle **`bundle--44f60a36-b83b-4eb5-ad54-9f86c2eaec0a`**, STIX 2.1.
- Source inventory and post-generation verification: [`aa26-222a-gunra-coverage-v1.json`](../../catalogs/intelligence/aa26-222a-gunra-coverage-v1.json). The STIX snapshot and catalog are reference material, not generation inputs or analyst events.

## Indicator inventory and reconciliation

The bundle has **80 objects**: 37 attack patterns, **29 indicators**, five relationships, three malware objects, two vulnerabilities, and one each of identity, report, location and marking definition. Object counts are not IOC counts. The raw snapshot preserves every object and relationship. The catalog retains all indicator IDs, raw patterns, dates and source descriptions, plus a contextual inventory of the other objects and unresolved references.

| Source indicator group | Objects | Representation |
| --- | ---: | --- |
| IPv4 equality | 17 | Independent historical network fixtures, `dest` |
| Domain equality | 4 | Recovered artifact metadata, `file_domain`; includes three `.onion` names and `datapub.news` |
| Email equality | 4 | Recovered contact artifact metadata, `file_email` |
| File hash AND filename | 4 | `file_hash` plus the correct basename in `file_path` on **the same event** |
| **Total** | **29** | All source patterns accounted for |

The `msmp.exe` indicator is `(SHA-1 OR SHA-256 OR MD5) AND file:name`. All three hash alternatives are represented, each with `msmp.exe` on its own file-metadata observation. `cryptor.exe` has one SHA-256 AND filename; two separate `main.exe` indicators carry different SHA-256 values AND the same filename. No unrelated hash and filename events are combined to claim a match.

Expanding all alternatives and retaining each source filename term gives **35 STIX assertions, 34 distinct typed values**: 17 IPs, four domains, four email addresses, six hashes (one SHA-1, four SHA-256, one MD5) and three distinct filenames. `main.exe` retains two source provenance assertions. Six hash assertions have same-event filename conditions. Requiring every OR alternative is stronger than satisfying one OR indicator, and ensures no supplied hash is omitted. This is explicit value/condition coverage of these known source patterns, not a general STIX language evaluator.

### Publication comparison

| Publication location | Comparison / treatment |
| --- | --- |
| Table 2, pp.10–11 | Same 17 IPs and four domain names as the STIX. Preserve the published first/last-seen intervals in the catalog; refang `[.]` without changing values. Historical addresses/domains are hunting leads, not proof of current maliciousness. |
| Table 3, p.11 | Same four ransom-negotiation email addresses as STIX. Use extracted file metadata, not fabricated mail transport. |
| Table 4, p.12 | Same four SHA-256/filename pairs as STIX. The `msmp.exe` SHA-1/MD5 alternatives are additional STIX values and are retained. |
| qTox list, p.11 | Four strings are absent from STIX indicator patterns; retain all four in `file_contact_id` fixtures. Join line wraps only. |
| Table 5, p.12 | `forticloud-sync` is absent from STIX indicator patterns; retain it as `file_account` in a hypothetical recovered configuration artifact. This does not create a Fortinet device or an account in inventory. |
| Impact section, p.8 / Table 18, p.17 | The body names `R3ADM3.txt`, while Table 18 prints `R34DM3.txt`. Keep both as independent file artifacts and document the inconsistency. Do not silently pick one spelling as universally correct. |
| pp.8,17 | Retain `.ENCRT`, the historical `.CRYPT` sample extension and Linux `.GNRA` as independent filename fixtures. These are not STIX equality patterns and do not prove encryption or recovery. |

The third printed qTox string contains a nonhex **`S`**. It is preserved exactly, without substituting a guessed hexadecimal character or claiming the string is a valid usable qTox ID. The STIX report's `published` is **August 7, 2026**, while the advisory's stated publication is **August 10, 2026**. Both values are retained with their separate meanings. The `cryptor.exe` object's description mentions another 40-character identifier outside its actual pattern; that source description remains in the catalog/snapshot, without inventing an additional typed indicator or correcting its label.

The combined catalog has **45 assertions, 44 distinct typed values**: 35 STIX assertions plus ten supplementary publication assertions (four qTox strings, one account, two note names and three extension patterns). All source indicator values are planted as supported analyst metadata. Equality coverage does not establish live reputation, effective malware behavior, real delivery of ransom messages or detection efficacy.

## Scenario adaptation

This is a **post-access** Windows branch followed by independent historical matching fixtures. The compromise of `prod-rdp-01` and the existing `LAB\admin` identity is a fictional prerequisite. The JSON does not claim to simulate initial Fortinet exploitation or turn a low-privilege account into an administrator. Reuse `prod-file-01`, `dc-01` and the base world services rather than inventing Fortinet, VDI or Hiware assets.

| Offset | Step | Source basis and evidence boundary |
| --- | --- | --- |
| +1 min | Network connection discovery | p.7, T1049. Invented `netstat` command on the assumed compromised host. |
| +10 min | Impacket SMB movement | p.6, T1021.002. Fictional Windows Python/tool installation paths, command line, logon and remote process ordering. |
| +20 min | Credential-access attempt | p.6, secretsdump.py/T1003.003. Process/SMB observations only; no successful NTDS extraction or pass-the-hash/ticket proof. |
| +30 min | Log-clearing attempt | p.7, T1685. Command launch does not prove logs were erased; continued sensor records are not a claim about effective impairment. |
| +35 min | File discovery | p.7, T1083. Invented directory command; not a native API trace. |
| +45 min | File read and archive | pp.7–10, T1005/T1560. File, archive, paths and arguments are fictional; not proof of uploaded content. |
| +55 min | Transfer observations | pp.7–10, Rclone/exfiltration behavior. Invented TEST-NET destination, config, duration and bytes; no mapping to Mega, OneDrive, SharePoint or a published IP. |
| +65 min | Shadowcopy deletion attempt | p.8, T1047/T1490. Uses source command structure with an invented GUID; no deletion success guarantee. |
| +75 min | Impact artifacts | p.8, `.ENCRT` and `R3ADM3.txt`. Fictional process filename and placement; metadata only, not encryption. |
| +85 min | Historical IP coverage | Every STIX IP, with fictional outbound direction/443, independent of the core compromise. |
| +86 min | Historical domain artifacts | Extracted names in hypothetical recovered evidence; no `.onion` public DNS or Tor session. |
| +87 min | Historical email artifacts | Extracted contact values; not email delivery, extortion success or negotiated payment. |
| +88 min | Historical sample metadata | Every supplied hash/filename pairing, including all `msmp.exe` alternatives. No sample execution. |
| +89 min | qTox and account artifacts | Additional publication strings in hypothetical recovered files; not qTox traffic or Fortinet telemetry. |
| +90 min | Other impact filename artifacts | Both note spellings and three suffixes. Linux `.GNRA` metadata uses generic `endpoint-lab.jsonl` on an existing Linux asset, not Sysmon or another causally linked victim compromise. |

The historical blocks are **not** a claim that every address, sample, contact, older leak-site domain and Linux/Windows variant appeared together in one incident. All directory paths, source file contents implied by extracted metadata, process PIDs, collector placements, host/account mappings, ordering, ports and byte amounts require synthetic assumptions. Collector `user` is the lab identity associated with the normalized observation; it does not establish local Linux account provisioning or permissions.

### Details kept as context or omitted from execution

- **CVE-2024-55591** and **CVE-2025-24472**, both source-described authentication bypasses affecting certain FortiOS/FortiProxy versions (CWE-288), remain catalog/notes context. No Fortinet inventory, invented request syntax, exploit success or finding record is created.
- SSL-VPN default credentials, absent lockout, OpenSSH download/tunneling, VDI session interception, OTP authentication-file backdoor, unused-account modification, Hiware symmetric-key theft, enterprise password decryption, successful credential dumping, pass-the-hash/ticket and authentication-session semantics are not simulated. The post-access prerequisite avoids claiming the supported process/flow fields prove these mechanisms.
- Native API calls, debugger checks, actual selective encryption, cryptographic key generation, weak-PRNG key reconstruction, real Linux ransomware execution, backup/data-center deletion, cloud tenant sessions, main.exe cloud collection, internal email collection, qTox/Tor sessions, cryptocurrency transfers and ransom negotiation are not executed or fabricated as successful outcomes.
- The publication describes a self-contained encryptor without observable DNS/HTTP. Accordingly, the scenario does not invent encryptor C2. Domain indicators appear in recovered-file enrichment, not network traffic attributed to the binary.
- The publication's tool list includes FileZilla, Amass, Rclone, Sliver, 7-Zip, WinRAR, DBeaver, Slack, Visual Studio Code, MobaXterm, AnyDesk, Google Remote Desktop, Mimikatz and Impacket. Only selected Impacket, archive and transfer behaviors are in the core chain; other tools remain alternatives/context. Legitimate software is not inherently malicious.
- All 37 STIX attack-pattern objects, the two CVEs, three malware objects, relationships and source qualifications remain available in the source snapshot and catalog. Selected evidence mappings identify attempts/metadata, not proven technique completion. No containment or recovery outcome is planted.

## Proposed exercise settings

These values are **synthetic choices**, not CISA incident measurements:

| Setting | Value | Reason |
| --- | --- | --- |
| Seed | 2 | Repeatable lab details |
| Start | `2026-08-11T00:00:00Z` | Arbitrary exercise time after publication. UTC is an assumed lab timezone; the source's late-night/early-morning observation does not establish actual victim UTC times. |
| Duration | 120 minutes | Contains fixed offsets through +90 minutes; structural minimum is 91 whole minutes |
| Inventory | 23 hosts | Existing lab inventory needed by the named references; not an affected-host count from CISA |
| Total events | 10,000 | 60 prescribed plus 9,940 routine observations if generated at these settings |
| Run folder | `output/gunra-v1-runNNN` | Automatically allocated from `output_name` |

STIX creation/modification/valid-from dates, the report publication metadata and historical first/last-seen dates stay in the source catalog. They do not replace these generator settings or assert that old infrastructure remained active on the synthetic exercise day.

## Validate, generate and check

Use the README's Python environment, then run from the extracted project folder:

```powershell
$python = '.\.venv\Scripts\python.exe'
$scenarioFile = '.\scenarios\cisa\aa26-222a-gunra-v1.json'
$coverageFile = '.\catalogs\intelligence\aa26-222a-gunra-coverage-v1.json'
$seed = 2
$startTime = '2026-08-11T00:00:00Z'
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

A generated package should report **45 assertions present, zero missing**. Only the scenario JSON goes into `create_dataset.py`; the catalog is a post-export check and the STIX is an authoring source. Match the source hash if replacing the source snapshot. If a catalog changes, reconcile it against the actual source again.

For Splunk lookups, match IPs against `dest`, domains against `file_domain`, email addresses against `file_email`, account names against `file_account`, qTox strings against `file_contact_id` and hashes against `file_hash`. Match filename/hash pairs within the same event. Contact strings use exact case-sensitive comparison in the checker; other string matching follows its documented normalization. These extracted fields are synthetic generic collector enrichment, not standard native Sysmon fields. Ingest only `events/*.jsonl` as `secdata:cim:json`; keep source snapshots, catalogs, manifests, context, truth and coverage reports outside the analyst index. Search All Time.

## Validation status

Validation-only reports **15 steps, 60 prescribed observations, minimum 91 minutes**, `dataset_generated: false`. Automated checks compile the scenario observations in memory, reconcile every source pattern term and verify all 45 coverage assertions, source byte hash and compound conditions. A correct hash and basename on different events must fail. Extracted artifact fields are restricted to `endpoint-lab.jsonl` filesystem records; no email transport or `.onion` DNS is invented. Existing scenario tests remain in the full suite.

No Gunra exercise dataset has been exported during authoring. Review the proposed branch/settings before running generation. These checks do not execute malware, contact real indicators, access AWS or ingest into Splunk, and do not establish effective detections or real cryptographic outcomes.
