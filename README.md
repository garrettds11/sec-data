# sec-data

Generate synthetic security events locally for Splunk investigations and detection tests. These instructions assume the repository is **already downloaded and extracted to your chosen folder**. Git is not required.

Follow steps 1–3 to prepare Python, check the project, and generate a verified Black Basta v2 dataset. Generation needs no AWS credentials, AI service, Splunk connection, or extra Python packages. Step 4 explains which files to ingest into Splunk.

The included example uses seed `2`, starts November 12, 2024 at 08:00 UTC, spans 120 minutes and produces 10,000 events. Black Basta v2 includes historical publication indicators; it is a synthetic exercise rather than a reconstruction of one victim.

## 1. Open PowerShell in the extracted project folder

The repository files are already downloaded and extracted wherever you want to keep them. Git is not required. Open that folder in File Explorer, type `powershell` in the address bar and press Enter. You can also open PowerShell normally and change to your actual folder:

```powershell
# Replace this example path with your extracted project folder.
Set-Location -LiteralPath 'C:\code\sec-data-main'
if (-not (Test-Path -LiteralPath '.\create_dataset.py' -PathType Leaf)) {
    throw 'Open the folder containing create_dataset.py, README.md, and the scenarios directory.'
}
```

Use the project folder itself, not its parent. Keep the extracted files and subfolders together. All commands below run from this folder.

Confirm that this copy contains Black Basta v2 and its checker:

```powershell
@(
    '.\validate_ioc_coverage.py',
    '.\scenarios\cisa\aa24-131a-black-basta-v2.json',
    '.\catalogs\intelligence\aa24-131a-publication-coverage-v2.json'
) | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
        throw "Required file missing: $_. Check the project folder and repository version."
    }
}
```

## 2. Prepare Python and check the repo

The default is **Python 3.15**. Install an approved, patched 64-bit build if needed, then reopen PowerShell and return to the extracted project folder. Python is the only additional installation required for local generation; Windows already supplies PowerShell. The core generator and tests use the standard library; no `pip install` is needed.

```powershell
py -3.15 --version
if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.15 with the Windows Python launcher before continuing.' }
```

Check whether the existing environment is already usable:

```powershell
$python = '.\.venv\Scripts\python.exe'
$reuseVenv = $false
if (Test-Path -LiteralPath $python -PathType Leaf) {
    & $python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 15) else 1)"
    $reuseVenv = ($LASTEXITCODE -eq 0)
}

if (-not $reuseVenv) {
    # Close processes using .venv first. Use a new shell with no venv activated.
    if (Test-Path -LiteralPath '.venv') {
        $backupRoot = '.\output\venv-backups'
        New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop | Out-Null
        $backupName = Join-Path $backupRoot ('venv-' + [guid]::NewGuid().ToString('N'))
        Move-Item -LiteralPath '.venv' -Destination $backupName -ErrorAction Stop
        Write-Host "Previous environment preserved as $backupName"
    }
    py -3.15 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
}

& $python --version
if ($LASTEXITCODE -ne 0) { throw 'Python environment is not usable.' }
& $python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Repo checks failed. Stop before generating data.' }
```

The suite should finish with `OK`. A renamed old venv is a backup for restoring to its original `.venv` location; do not run it from the backup path. You do not need to activate the new environment or change PowerShell execution policy. In VS Code select `.venv\Scripts\python.exe`. See [Python migration details](docs/python-version.md) for compatibility and optional uploader dependencies.

## 3. Generate and verify Black Basta v2

Run this entire block from the extracted project folder. Every run variable is defined here, so it also works in a new PowerShell window after setup. A unique output directory prevents accidental reuse of an existing run.

```powershell
$python = '.\.venv\Scripts\python.exe'
$seed = 2
$startTime = '2024-11-12T08:00:00Z'
$durationMinutes = 120
$targetEvents = 10000
$hostCount = 23
$scenarioFile = '.\scenarios\cisa\aa24-131a-black-basta-v2.json'
$coverageFile = '.\catalogs\intelligence\aa24-131a-publication-coverage-v2.json'
$outputDir = Join-Path '.\output' ('aa24-131a-black-basta-v2-' + [guid]::NewGuid().ToString('N'))

& $python .\validate_scenario.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount `
    --duration-minutes $durationMinutes --target-events $targetEvents
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed.' }

& $python .\create_dataset.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount --start-time $startTime `
    --duration-minutes $durationMinutes --target-events $targetEvents `
    --output-dir $outputDir
if ($LASTEXITCODE -ne 0) { throw 'Dataset generation failed.' }

& $python .\validate_ioc_coverage.py --dataset-dir $outputDir `
    --coverage-file $coverageFile `
    --output (Join-Path $outputDir 'ioc-coverage-report.json')
if ($LASTEXITCODE -ne 0) { throw 'Publication indicator coverage failed.' }

$manifest = Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.event_records -ne $targetEvents) { throw 'Unexpected event count.' }
Write-Host "Verified $($manifest.event_records) events in $outputDir"
Get-ChildItem -LiteralPath (Join-Path $outputDir 'events') -Filter '*.jsonl' -File
```

Expected results for these settings:

| Check | Expected |
| --- | --- |
| Scenario | `cisa-aa24-131a-black-basta-composite-v2` |
| Total events | 10,000 |
| Prescribed story/coverage observations | 280 |
| Routine observations | 9,720 |
| Publication coverage | 261 assertions present, 0 missing; 241 distinct typed values |
| Event-time window | November 12, 2024, 08:00 to before 10:00 UTC |
| Output | A new directory under `output/`, printed by the block |

Seed `2` selects repeatable details. It does not select the plot or alter literal publication IOCs. The scenario file selects the plot. The catalog checks exported event fields after generation; it is not a second generation input. Unique output-directory names do not randomize the generated data.

This exercise covers the selected May publication tables plus the retained November set. It is a deliberately broad historical matching fixture, not one documented victim timeline. **Exact agreement with your converted STIX CSV has not been established.** See the [v2 source and coverage notes](docs/examples/aa24-131a-black-basta-v2-notes.md).

## 4. Choose the files for Splunk

| Output | Purpose | Ingest as security events? |
| --- | --- | --- |
| `events/*.jsonl` | Analyst observations | Yes, with sourcetype `secdata:cim:json` |
| `context/` | Assets, identities and other reference data | No |
| `truth/` | Private scenario answer key | No |
| `dataset-manifest.json` and `ioc-coverage-report.json` | Counts, parameters, hashes and indicator verification | No |

Keep the printed output path. The events use the configured November 2024 time window, regardless of when you generate or ingest them. Search **All Time** in Splunk. Use a fresh index for an isolated count check and do not ingest the same run twice.

## Use the events in Splunk

Install the official [Splunk Common Information Model add-on](https://splunkbase.splunk.com/app/1621) separately. This project was tested with version 8.7.0. For a local Windows Splunk installation, copy this repository's [TA-sec-data-cim add-on](splunk/TA-sec-data-cim/) into Splunk's apps directory from an elevated PowerShell, then restart Splunk:

```powershell
Copy-Item .\splunk\TA-sec-data-cim 'C:\Program Files\Splunk\etc\apps' -Recurse -Force
splunk restart
```

Create the `sec_data` index before ingesting: in Splunk Web, select **Settings → Indexes → New Index**, or run `splunk add index sec_data` once from the CLI. Splunk can report that `add oneshot` queued a file even when it later drops the events because the index does not exist. Ingest **only** `events/*.jsonl` with sourcetype `secdata:cim:json`. The following uses `$outputDir` from step 3 above. In a new PowerShell session, return to your project folder and set `$outputDir` to the exact generated run path first. With `splunk` on your PATH:

```powershell
$indexName = 'sec_data'
Get-ChildItem -LiteralPath (Join-Path $outputDir 'events') -Filter '*.jsonl' -File | ForEach-Object {
    splunk add oneshot $_.FullName -index $indexName -sourcetype secdata:cim:json
}
```

Confirm the ingest before investigating. In PowerShell, read the expected count from this run's manifest:

```powershell
(Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json') -Raw | ConvertFrom-Json).event_records
```

In Splunk, select **All Time** and run:

```spl
index=sec_data earliest=0
| stats count
```

The two counts must match when the index contains only this run. If you have indexed earlier runs into `sec_data`, use a fresh index for an exact comparison and update the index name in both the ingest command and search. A successful `add oneshot` message alone does not confirm that Splunk indexed the events.

To inspect a run by CIM dataset, search **All Time**. the walkthrough uses the November 2024 window:

```spl
index=sec_data sourcetype=secdata:cim:json
| stats count by sec_data_cim_dataset
```

Splunk assigns `host`, `source`, `sourcetype`, `index`, and `splunk_server` at ingest; the JSON supplies the modeled observation fields and UTC `time`. The project add-on handles event boundaries, field extraction, event types, tags, and DNS arrays. The [lab report](docs/splunk-validation.md) records checks on the planted fixture in Splunk Enterprise 10.4.0 with CIM 8.7.0. The high-volume background stream has not undergone that live validation.

For the index, sourcetype, and source values to expect after upload, see the [post-ingest source inventory](docs/dataset.md#expected-source-inventory-in-splunk).

## Choose a volume

`--target-events` sets an exact published count. The manifest lists counts by source and by planted or ordinary origin; the [dataset guide](docs/dataset.md) records the reference run's measured distribution. To make a million-event run, set a new directory and rerun the generation command above:

```powershell
$targetEvents = 1000000
$outputDir = Join-Path '.\output' ('black-basta-v2-1m-' + [guid]::NewGuid().ToString('N'))
& $python .\create_dataset.py --scenario-file $scenarioFile `
  --seed $seed --host-count $hostCount --start-time $startTime `
  --duration-minutes $durationMinutes --target-events $targetEvents `
  --output-dir $outputDir
```

A million-event package may approach a 500 MB/day Splunk license limit; read the actual `events/` byte totals in its manifest before ingest. A full million-event export and live Splunk ingest have not yet been measured for this design. See the [scale guide](docs/scale.md) for measurement details.

### Time coverage

`$startTime` and `$durationMinutes` define the routine-event window. The reference story also includes a baseline assessment before that window. Increasing `$targetEvents` makes events denser within the same interval; set `$durationMinutes = 240` for a four-hour window that also spaces the planted operations farther apart. Each JSON event includes its own UTC timestamp for Splunk event-time extraction. The [dataset guide](docs/dataset.md#time-scale-and-interpretation) records the measured time span of the reference run.

### Keep a reproducible run

Keep the repository ZIP or extracted source version alongside the scenario and `dataset-manifest.json`. Record the seed, UTC start time, duration, host count and target event count. Reuse those exact inputs and source version to reproduce a run. The manifest records parameters and file hashes. Choose a new output directory each time. Standalone finding exports also need an explicit `--as-of` or `--snapshots` value for repeatable assessment dates.

## Other workflows and scenario authoring

The scenario file selects the story. The unsuffixed `scenarios/cisa/aa24-131a-black-basta.json` is v1 with narrower indicator coverage. Omitting `--scenario-file` selects the built-in reference investigation. Changing the seed does not choose another story.

| Task | Entry point | Result |
| --- | --- | --- |
| Generate events for Splunk | `create_dataset.py` | Source-specific `events/` for ingest, `context/` for reference, and `truth/` for validation |
| Author a different investigation | `--scenario-file` with `scenarios/file-collection.json` as a model | The same event package with authored steps and ordinary activity |
| Inspect the source story | `create_story.py` | Source-format observations, shared world data, timeline, and answer key |
| Export standalone findings | `create_vuln_table.py`, `create_compliance_table.py` | JSON or JSONL for local analysis or the optional AWS uploader |

The seed changes reproducible details, not the investigation plot. A scenario JSON file changes the plot without editing generator code. An LLM can author that file using the [scenario contract](docs/scenarios.md); the generator validates and compiles it. It does not accept free-form natural language as a direct CLI argument. See the [documentation index](docs/README.md) for the complete workflow.

## Choose your workflow

**Story source and authoring assistance are independent choices.** Choose CISA-oriented, AI-generated, or human-generated content, then author/customize its one scenario JSON manually or with AI help. The generator itself uses no AI service.

| Story source | Without AI assistance | With AI assistance |
| --- | --- | --- |
| CISA-oriented | Read the full advisory, follow the [CISA authoring guide](docs/cisa-scenario-authoring.md), and edit the JSON yourself. | Use the CISA prompt below; the agent follows that same guide and identifies fictional additions. |
| AI-generated | Manually review/edit a previously AI-proposed story or scenario; subsequent generation needs no AI. | Use the generic prompt below to request a plausible fictional story. |
| Human-generated | Write your narrative and follow [manual authoring/customization](docs/scenario-authoring.md). | Supply your narrative and ask AI to translate it into the current contract. |

To **run without AI**, use the included Black Basta walkthrough above or follow the [manual workflow](docs/scenario-authoring.md) for a custom input. To **author with AI**, follow [AI authoring](docs/ai-authoring.md), including the attachment checklist for chats without access to your project files. Both paths converge on validation, generation and the same Splunk ingest instructions.

Generic AI prompt (defaults to an AI-generated plausible story):

~~~text
create a threat story and generate synthetic data using the capabilities provide by this repo, https://github.com/garrettds11/sec-data
~~~

CISA-focused AI prompt (replace [ID]):

~~~text
create a threat story and generate synthetic data using one scenario JSON file based on CISA advisory [ID]. Follow the repo’s current scenario contract. Preserve documented facts, identify fictional additions separately, and propose the ordered story steps before generating data. Explain any details the current generator cannot represent. Details from the CISA publication should be used, including the IOCs, tactics, techniques, software, and weaknesses.
~~~

A repository-aware agent should read AGENTS.md, propose steps/settings and wait for your approval before generating a dataset. An ordinary chat needs the contract, example and inventory/field references attached; your local project folder is not automatically visible to it. A CISA catalog row helps select a publication but does not replace its full text and revision. See the [Black Basta worked example](docs/examples/aa24-131a-black-basta-notes.md).

## Other commands

The standalone vulnerability and compliance commands retain their JSON and JSONL outputs for the optional AWS uploader. They are separate from the CIM event package. Specify `--as-of` when you need repeatable assessment dates; `--target-records` requests an exact applicable finding count or fails if the selected inventory and catalogs cannot supply it.

```powershell
$findingHostCount = 3000
$findingTarget = 10000
$vulnOutput = '.\output\vuln-10k.jsonl'
$complianceOutput = '.\output\compliance.jsonl'
& $python .\create_vuln_table.py --seed $seed --as-of $startTime `
  --host-count $findingHostCount --target-records $findingTarget `
  --format jsonl --output $vulnOutput
& $python .\create_compliance_table.py --seed $seed --as-of $startTime `
  --host-count $findingHostCount --format jsonl --output $complianceOutput
```

`create_story.py` builds the fixed source story used internally and in the checked-in [reference fixture](tests/fixtures/README.md). `create_recon_events.py` and `create_cim_events.py` remain available for source-format experiments and projection of existing bundles. Use `create_dataset.py` for the single CIM-shaped analyst event package.

Run the checks locally:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

For field decisions, output layout, and investigation limits, read the [dataset guide](docs/dataset.md), [CIM guide](docs/cim.md), and [story guide](docs/story.md).

## Limits and optional upload

All records are synthetic. The generated Zeek-shaped and Windows-shaped reference files are not exact vendor raw events, and the project does not scan systems or provide official CIS Benchmark content. Five source observations and one TLS metadata observation lack a sound CIM mapping in the current dataset. The planted read and later upload support a correlation exercise; they do not prove which file bytes were transferred.

Only the separate [AWS uploader](upload_to_aws.py) contacts AWS. It accepts the standalone vulnerability and compliance outputs, requires `boto3` and configured credentials, and may create or upsert DynamoDB items with associated cost. For example, after generating `$vulnOutput`:

```powershell
& $python -m pip install boto3
$awsRegion = 'us-east-1'
& $python .\upload_to_aws.py --dataset vuln --input $vulnOutput --region $awsRegion
```

The uploader prompts for a profile when one is not supplied and requires an explicit `UPLOAD` confirmation before writing. See the [Windows work instructions](docs/work-instructions-windows-vscode.md) for credentials and table details.

## License

See [LICENSE](LICENSE) and the [release notes](CHANGELOG.md).
