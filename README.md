# sec-data

Generate synthetic security events from a scenario JSON file for Splunk investigations and detection testing. The generator writes analyst events, reference inventory, a private answer key, and a manifest with counts and file hashes.

These Windows PowerShell instructions assume the project files are already extracted to your chosen folder. Git is not required. Local generation uses the Python standard library and requires no AWS credentials, AI service, or Splunk connection.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+.
- A patched Python 3.15 installation with the Windows `py` launcher; 64-bit is recommended.
- The complete extracted project folder, including `common/`, `catalogs/`, and `scenarios/`.

Python 3.15 is the repository default. CI also checks Python 3.12 compatibility on Windows and Linux. See [Windows requirements](docs/windows-software-requirements.md) for tooling details.

## 1. Open the project folder

Open PowerShell in the folder containing `create_dataset.py` and `README.md`. Alternatively, replace the example path below with your actual project folder:

```powershell
Set-Location -LiteralPath 'C:\code\sec-data-main'
if (-not (Test-Path -LiteralPath '.\create_dataset.py' -PathType Leaf)) {
    throw 'Select the project folder containing create_dataset.py.'
}
```

Run all subsequent commands from this folder.

## 2. Set up Python

Create the local environment if it does not exist, then verify its interpreter:

```powershell
py -3.15 --version
if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.15 with the Windows py launcher.' }

if (-not (Test-Path -LiteralPath '.venv')) {
    py -3.15 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
}

$python = '.\.venv\Scripts\python.exe'
& $python -c "import sys; print(sys.version); raise SystemExit(0 if sys.version_info[:2] == (3, 15) else 1)"
if ($LASTEXITCODE -ne 0) { throw 'The existing .venv is not usable with Python 3.15. Follow docs/python-version.md to rebuild it.' }

& $python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Project checks failed. Resolve the failure before generating data.' }
```

The tests should finish with `OK`. No `pip install`, environment activation, or PowerShell execution-policy change is needed. For an older or broken environment, follow the [Python migration guide](docs/python-version.md).

## 3. Select a scenario and generate data

Set `$scenarioFile` to the JSON file you want to run. Included examples:

| Scenario file | Purpose |
| --- | --- |
| `scenarios/file-collection.json` | Small authored file-collection investigation |
| `scenarios/cisa/aa26-222a-gunra-v1.json` | Gunra AA26-222A with full uploaded-STIX value coverage; [settings and catalog](docs/examples/aa26-222a-gunra-v1-notes.md) |
| `scenarios/cisa/aa26-293a-safepay-v1.json` | SafePay AA26-293A with uploaded-STIX and publication coverage; [settings and catalog](docs/examples/aa26-293a-safepay-v1-notes.md) |
| `scenarios/cisa/aa24-131a-black-basta-v2.json` | Black Basta exercise with historical publication indicator coverage |
| `scenarios/cisa/aa24-131a-black-basta.json` | Earlier Black Basta v1 adaptation with six network indicators |

Use a generator-compatible scenario JSON, not a raw STIX bundle. To use your own scenario, follow the [scenario contract](docs/scenarios.md). Omitting `--scenario-file` selects a separate built-in reference story.

Run this complete block after choosing the settings at its top. The example selects Black Basta v2. Change `$scenarioFile` to select another scenario; change the remaining settings to fit that scenario's requirements.

```powershell
$python = '.\.venv\Scripts\python.exe'
$scenarioFile = '.\scenarios\cisa\aa24-131a-black-basta-v2.json'
$seed = 2
$startTime = '2024-11-12T08:00:00Z'
$durationMinutes = 120
$targetEvents = 10000
$hostCount = 23
$outputRoot = '.\output'

if (-not (Test-Path -LiteralPath $scenarioFile -PathType Leaf)) {
    throw "Scenario file does not exist: $scenarioFile"
}

& $python .\validate_scenario.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount `
    --duration-minutes $durationMinutes --target-events $targetEvents
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed. Review the reported requirements.' }

$runJson = & $python .\create_dataset.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount --start-time $startTime `
    --duration-minutes $durationMinutes --target-events $targetEvents `
    --output-root $outputRoot --json
if ($LASTEXITCODE -ne 0) { throw 'Dataset generation failed.' }
$outputDir = ($runJson | ConvertFrom-Json).output_dir

$manifest = Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.event_records -ne $targetEvents) { throw 'Unexpected event count.' }
Write-Host "Generated $($manifest.event_records) events in $outputDir"
Get-ChildItem -LiteralPath (Join-Path $outputDir 'events') -Filter '*.jsonl' -File
```

| Setting | Meaning |
| --- | --- |
| `$scenarioFile` | Selects the story and its prescribed observations |
| `$seed` | Makes generated details repeatable; does not change the plot or literal scenario IOCs |
| `$startTime` | UTC start time for the synthetic event timeline |
| `$durationMinutes` | Generation window; must meet the scenario's minimum duration |
| `$targetEvents` | Exact total count, including prescribed observations and routine activity |
| `$hostCount` | Inventory size; must support the scenario's asset references |
| `$outputRoot` | Parent folder for automatically named runs; defaults to `output/` |

Validation checks structural compatibility and reports minimum duration and prescribed counts. It does not establish source fidelity, causal plausibility, or indicator coverage. Increasing the event count adds routine activity; it does not add publication indicators. Keep the same seed, host count, duration and target count in validation and generation.

The example settings produce 10,000 events for Black Basta v2: 280 prescribed observations and 9,720 routine observations, dated November 12, 2024 from 08:00 to before 10:00 UTC. Other scenarios have different prescribed counts. Publication dates and the current date do not replace the configured synthetic event window.

Keep the printed output path. Run folders use the scenario’s optional `output_name`, such as `black-basta-v2-run001`, then `run002`. Without that field, a safe form of the scenario ID is used. Numbered folders are unique within the output root while existing runs are retained; deleted names may be reused. Concurrent generators reserve separate names atomically. Folder names do not randomize the data. Use `--output-dir PATH` instead of `--output-root` to choose an explicit new directory. Preserve the source version, scenario and manifest to reproduce a run.

## 4. Check publication indicators when applicable

For Black Basta v2, run this additional check against the output from step 3:

```powershell
$python = '.\.venv\Scripts\python.exe'
$coverageFile = '.\catalogs\intelligence\aa24-131a-publication-coverage-v2.json'
& $python .\validate_ioc_coverage.py --dataset-dir $outputDir `
    --coverage-file $coverageFile `
    --output (Join-Path $outputDir 'ioc-coverage-report.json')
if ($LASTEXITCODE -ne 0) { throw 'Publication indicator coverage failed.' }
```

If you opened a new PowerShell window, return to the project folder and set `$outputDir` to the exact run directory first. The report path must be new; omit `--output` to print the report again without overwriting it.

Black Basta v2 should report **261 assertions present, 0 missing**, covering 241 distinct typed values. These are indicator assertions, not event counts. The catalog verifies actual exported event fields and is not a second generation input. For another scenario, use its matching coverage catalog if one exists; skip this step if it has none.

V2 deliberately combines historical May publication tables with the retained November set. It is a broad matching exercise, not one documented victim timeline. Coverage of those publication tables does not establish exact parity with a STIX attachment or a converted CSV. See the [Black Basta v2 notes](docs/examples/aa24-131a-black-basta-v2-notes.md) for sources and limits.

## 5. Use the output in Splunk

| Output | Purpose | Index as security events? |
| --- | --- | --- |
| `events/*.jsonl` | Analyst-facing synthetic observations | Yes |
| `context/` | Assets, identities and other reference inventory | No |
| `truth/` | Private story descriptions and answer key | No |
| `dataset-manifest.json` | Generation parameters, counts and file hashes | No |
| `ioc-coverage-report.json`, when generated | Indicator verification and supporting event IDs | No |

Install [TA-sec-data-cim](splunk/TA-sec-data-cim/) at the Splunk parsing tier before ingestion so the JSON `time` field becomes event time. Install the [Splunk Common Information Model add-on](https://splunkbase.splunk.com/app/1621) for CIM use. For a local Windows Splunk installation, copy the project add-on from an elevated PowerShell, then restart Splunk:

```powershell
Copy-Item .\splunk\TA-sec-data-cim 'C:\Program Files\Splunk\etc\apps' -Recurse -Force
splunk restart
```

Create the destination index first, using **Settings → Indexes → New Index** in Splunk Web. Use a fresh index to compare counts for a single run. With the Splunk CLI on your PATH, ingest only the event files:

```powershell
# Set this to the index you created.
$indexName = 'sec_data'
Get-ChildItem -LiteralPath (Join-Path $outputDir 'events') -Filter '*.jsonl' -File | ForEach-Object {
    splunk add oneshot $_.FullName -index $indexName -sourcetype secdata:cim:json
    if ($LASTEXITCODE -ne 0) { throw "Ingestion command failed for $($_.FullName)" }
}
```

This uses `$outputDir` from step 3. If Splunk is on another machine, transfer the verified output there and set the path accordingly. Do not ingest the same run twice.

Select **All Time** in Splunk and search, replacing the index name if needed:

```spl
index=sec_data sourcetype=secdata:cim:json earliest=0
| stats count
```

Compare that count with the manifest:

```powershell
(Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json') -Raw | ConvertFrom-Json).event_records
```

For an isolated run, the counts must match. A successful `add oneshot` response means the file was queued; confirm that Splunk actually indexed it. Event timestamps follow the generation settings, regardless of upload date.

Inspect the source distribution with:

```spl
index=sec_data sourcetype=secdata:cim:json earliest=0
| stats count by sec_data_cim_dataset
```

The [Splunk validation report](docs/splunk-validation.md) records the measured lab scope. Publication coverage checks do not validate your Splunk lookup normalization, field extraction, or detection rules.

## Troubleshooting

| Problem | Action |
| --- | --- |
| `create_dataset.py` cannot be found | Open the project folder itself, not its parent |
| `py -3.15` is unavailable | Install/repair Python 3.15 and its launcher, then reopen PowerShell |
| Existing `.venv` uses older or removed Python | Follow the [migration guide](docs/python-version.md) |
| Scenario validation fails | Review its minimum duration, event count, inventory references and supported fields |
| Output directory exists | Rerun the complete generation block to choose a new directory |
| Coverage fails | Confirm that the scenario and coverage catalog match; inspect the report before ingesting |
| Splunk count is missing or wrong | Confirm the index exists, search All Time, check parsing and compare this run's manifest |

## Additional documentation

- [Scenario authoring](docs/scenario-authoring.md): write or customize a scenario.
- [CISA authoring](docs/cisa-scenario-authoring.md): retrieve the published STIX JSON, reconcile its indicators with the advisory, preserve source facts and identify fictional additions.
- [AI assistance](docs/ai-authoring.md): use AI to author a compatible scenario file.
- [Dataset guide](docs/dataset.md): output layout, fields, counts and time interpretation.
- [Scale guide](docs/scale.md): larger runs and standalone finding exports.
- [Windows work instructions](docs/work-instructions-windows-vscode.md): VS Code and optional AWS upload.
- [Documentation index](docs/README.md): all guides.

All records are synthetic. The generator does not execute malware or scan systems; its source-shaped events are not exact vendor raw telemetry. The optional [AWS uploader](upload_to_aws.py) is separate from local event generation, requires `boto3` and AWS permissions, and can incur AWS costs.

## License

See [LICENSE](LICENSE) and [CHANGELOG.md](CHANGELOG.md).
