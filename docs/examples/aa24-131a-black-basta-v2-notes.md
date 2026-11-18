# Black Basta scenario v2 — historical publication indicator coverage

## What changed

Use `scenarios/cisa/aa24-131a-black-basta-v2.json` when the objective is matching the original publication's IOCs as well as v1's November set. V1 remains unchanged at `scenarios/cisa/aa24-131a-black-basta.json`; it is a six-network-indicator, November-revision adaptation. V2 retains that 23-step fictional story and adds four separately described historical coverage blocks. It has **27 steps, 280 prescribed observations**, and **9,720 routine observations** in a 10,000-event run.

The input JSON remains scenario schema version 1. The scenario's own identity/version is v2. New `file_hash` / `process_hash` fields require the generator changes shipped with v2; an older checkout rejects those fields rather than silently omitting them. No malware is downloaded, created, or executed. Filesystem paths and command lines are event metadata only.

This is a comprehensive matching fixture for the selected publication tables, not a reconstruction of one victim. Giving one exercise every historical IOC is intentionally broader than a plausible single affiliate's operation. Supplemental Linux sample observations are independent evidence, not invented lateral movement into a new Linux victim. An indicator match is not proof of infection or present maliciousness, particularly for shared IPs and suspected domains.

## Sources and exact scope

| Source | Version | Coverage |
| --- | --- | --- |
| [CISA initial publication](https://www.cisa.gov/sites/default/files/2024-05/aa24-131a-joint-csa-stopransomware-black-basta_1.pdf) | May 10, 2024, 17 pages | Tables 7–11, including hash, IP, domain and file-path values |
| [Official July rendering of the initial publication](https://www.cisa.gov/sites/default/files/2024-07/aa24-131a-joint-csa-stopransomware-black-basta_2.pdf) | Initial-version text | Cross-check for the malformed indexed cell containing `fafaff3d...91b3e08`; not used to replace the May table set |
| [CISA revision](https://www.cisa.gov/sites/default/files/2024-11/aa24-131a-joint-csa-stopransomware-black-basta_3.pdf), also [official FBI copy](https://www.ic3.gov/CSA/2024/240511.pdf) | November 8, 2024, 10 pages | Preserve v1's four IPs, two domains and behavioral basis |

Sources were reviewed on November 18, 2026. Direct CISA requests returned HTTP 403; its indexed May PDF text supplied the complete contiguous IOC tables. The source inventory retains the source rows to make review possible. November explicitly supersedes old indicators; v2 deliberately includes both sets for historical testing and identifies their revisions independently. It does not claim that May indicators remain operational in November or today.

**The original STIX attachment and the user's converted CSV were not available for byte-level inspection. This is verified publication-table coverage, not a claim of exact STIX/CSV parity.** STIX may include additional objects, distinct versions, patterns or other values; those require reconciliation against the actual attachment. Context objects and duplicate provenance rows are not automatically distinct indicators.

## Source inventory and measured coverage

`catalogs/intelligence/aa24-131a-publication-coverage-v2.json` preserves source table rows, normalization rules, revisions, classifications, and 261 assertions linked to intended scenario steps. It is a post-export verification input, not an additional generation input.

| May table | Published row count | Representation |
| --- | ---: | --- |
| 7 — Malicious files | 44 | Published SHA-256 in `file_hash`; original Rclone hash also in `process_hash` |
| 8 — Network indicators | 45 | Each supplied IP in `dest`; domain/suffix strings in description cells also represented in DNS `query` |
| 9 — File indicators | 33 | Source paths/names in `file_path`, accompanying hashes in `file_hash`; multiple paths from one row retain provenance |
| 10 — Known Cobalt Strike domains | 47 | DNS `query` |
| 11 — Suspected domains | 46 | DNS `query`; source suspicion retained in catalog/truth |
| November Tables 7–8 | 6 | V1's IP `dest` and domain `query` observations |

All rows, including repeated source rows, are accounted for. The 261 assertions cover **241 distinct type/value indicators**: 44 IPv4 addresses, 110 domains, 56 SHA-256 hashes, 3 MD5 hashes and 28 path/name patterns. Counts include both revisions. Multiple assertions can be satisfied by one event, and one event can carry a path and hash. These totals are not event totals or counts for the unavailable STIX file.

Normalization is explicit:

- `[.]` becomes `.`, DNS and hash matching ignores case; SHA/MD5 hex digits are unchanged.
- Hash algorithm labels are inferred from 64/32 hexadecimal characters in the generic Hash columns; they are not independent cryptographic verification. Matching uses the digest string.
- Hash tokens wrapped by PDF extraction have whitespace removed. One broken HTML cell was cross-checked against the official alternate rendering.
- Renderer-doubled backslashes become Windows separators, and `Musi c` becomes `Music` where the extracted redacted path wrapped the word.
- Redacted components and published wildcard paths remain patterns in the catalog, with a fictional representative in events. Basename-only indicators use basename matching. A published suffix `.rasapool.net` is represented by an apex query, not a claim of complete suffix-search testing.
- Source table descriptions containing both domains and IPs do not cause us to invent a successful DNS mapping. All supplemental domain responses are NXDOMAIN.
- ELF sample hashes use a Linux host and generic `endpoint-lab.jsonl` filesystem observations. EXE/DLL and Windows paths use Windows hosts. Generic sample names are fictional when only a type was published.

## Sequence and fictional additions

V1's ordered story, tool/CVE selections and limitations remain described in [the v1 notes](aa24-131a-black-basta-notes.md). V2 changes neither the original six network indicator values nor the default 120-minute run envelope. Source-defined hash metadata is added to the suspicious Rclone process; no executable bytes are present.

| Offset | Added block | Interpretation |
| --- | --- | --- |
| +10 minutes | May domain coverage | DNS queries, no successful resolution or C2 inference |
| +11 minutes | May IP coverage | Independent network observations, including shared infrastructure; not all asserted malicious |
| +52 minutes | May sample hashes | Published sample fingerprints in synthetic file metadata, not execution proof |
| +53 minutes | May file artifacts | Source filenames/paths and associated hashes; repeated path/hash variants are independent samples |

The Windows/Linux hosts, process placement, literal ports, bytes, timing and observed outcomes are synthetic. Coverage blocks do not assert that every listed object appeared in one incident. Existing account privilege, successful credential theft, AV/EDR disabling, encryption, and containment limitations remain unchanged. The NXDOMAIN choices and invented command paths are not source facts.

## Validate, generate, then check coverage

Use the approved Python environment from the repository root. Set a NEW output directory. Only the scenario JSON is passed into generation.

```powershell
$python = '.\.venv\Scripts\python.exe'
$scenarioFile = '.\scenarios\cisa\aa24-131a-black-basta-v2.json'
$coverageFile = '.\catalogs\intelligence\aa24-131a-publication-coverage-v2.json'
$outputDir = '.\output\aa24-131a-black-basta-v2-run-01'

& $python .\validate_scenario.py --scenario-file $scenarioFile `
  --seed 2 --host-count 23 --duration-minutes 120 --target-events 10000
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed.' }

& $python .\create_dataset.py --scenario-file $scenarioFile `
  --seed 2 --host-count 23 --start-time '2024-11-12T08:00:00Z' `
  --duration-minutes 120 --target-events 10000 --output-dir $outputDir
if ($LASTEXITCODE -ne 0) { throw 'Generation failed.' }

& $python .\validate_ioc_coverage.py --dataset-dir $outputDir `
  --coverage-file $coverageFile `
  --output (Join-Path $outputDir 'ioc-coverage-report.json')
if ($LASTEXITCODE -ne 0) { throw 'Publication indicator coverage failed.' }
```

A successful check reports **261 present, 0 missing** and links each assertion to actual event IDs, files and times. It reads only `events/*.jsonl`, not context, truth or descriptions. It fails on a mismatched scenario identity or missing values. It compares explicit fields; a hash in a narrative cannot satisfy a hash assertion. The optional report is written only to a new path; omitting `--output` prints the complete report without writing anything.

For an independent v2 run, structural validation still needs at least 280 target events and 111 whole minutes. Increasing total events adds background, not more source IOCs. At the documented settings, all events remain on November 12, 2024 between 08:00 and 10:00 UTC. Source observation/publication dates in the catalog do not override runtime time.

## Splunk use

Ingest only the new run's `events/*.jsonl`, with `secdata:cim:json`. Keep context, truth, source catalog, manifests and the coverage report outside the analyst index. Use a fresh index or isolate the new source paths so a re-ingest does not duplicate old records.

Correlate domains against `query`; IPs against `dest`; hashes against `file_hash` and/or `process_hash`; source artifact names against `file_path`. Defang normalization and case-insensitive matching may also be needed in your lookup definition. This repository does not automatically import STIX or configure a Splunk lookup/correlation search. Publication-field coverage is separate from validating your uploaded CSV, Splunk extraction, time selection, lookup normalization and detection rules.

Examples in Search (All Time, replacing the index name):

```spl
index=YOUR_V2_INDEX sourcetype=secdata:cim:json
| search query="trailshop.net" OR query="realbumblebee.net" OR dest="66.249.66.18"
| table _time source query dest event_id
```

```spl
index=YOUR_V2_INDEX sourcetype=secdata:cim:json
| search file_hash="0112e3b20872760dda5f658f6b546c85f126e803e27f0577b294f335ffa5a298"
    OR process_hash="0112e3b20872760dda5f658f6b546c85f126e803e27f0577b294f335ffa5a298"
| table _time source dest file_path process file_hash process_hash event_id
```

## Verification and limits

Automated checks export 10,000 events, reconcile 280 prescribed/9,720 routine observations, check all 261 assertions, confirm timestamps and truth separation, and confirm a removed DNS IOC causes a failing coverage report even while context and truth still contain the story. Hash tests reject malformed digests and incorrect dataset placement. Source-inventory checks account for every published table row.

Tests validate synthetic metadata, not exploitability, actor attribution, current IOC reputation, malware content, native vendor telemetry, or effective security controls. No live IOC traffic or live AWS/Splunk action is performed. Exact original STIX/consumer CSV reconciliation remains outstanding until those files are supplied.
