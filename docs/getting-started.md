# Start or return to sec-data (Windows PowerShell)

Follow these steps in order. This is the complete path for the included **Black Basta v2 publication-coverage exercise**, included in the current repository version. It generates local synthetic files; it needs no AWS credentials, AI service, live malware, or Splunk connection.

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

The suite should finish with `OK`. A renamed old venv is a backup for restoring to its original `.venv` location; do not run it from the backup path. You do not need to activate the new environment or change PowerShell execution policy. In VS Code select `.venv\Scripts\python.exe`. See [Python migration details](python-version.md) for compatibility and optional uploader dependencies.

## 3. Generate and verify Black Basta v2

Run this entire block from the extracted project folder. Every run variable is defined here, so it also works in a new PowerShell window after setup. The generator allocates a readable, unused run directory automatically.

```powershell
$python = '.\.venv\Scripts\python.exe'
$seed = 2
$startTime = '2024-11-12T08:00:00Z'
$durationMinutes = 120
$targetEvents = 10000
$hostCount = 23
$scenarioFile = '.\scenarios\cisa\aa24-131a-black-basta-v2.json'
$coverageFile = '.\catalogs\intelligence\aa24-131a-publication-coverage-v2.json'
$outputRoot = '.\output'

& $python .\validate_scenario.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount `
    --duration-minutes $durationMinutes --target-events $targetEvents
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed.' }

$runJson = & $python .\create_dataset.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount --start-time $startTime `
    --duration-minutes $durationMinutes --target-events $targetEvents `
    --output-root $outputRoot --json
if ($LASTEXITCODE -ne 0) { throw 'Dataset generation failed.' }
$outputDir = ($runJson | ConvertFrom-Json).output_dir

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

Seed `2` selects repeatable details. It does not select the plot or alter literal publication IOCs. The scenario file selects the plot. The catalog checks exported event fields after generation; it is not a second generation input. The scenario declares `output_name: black-basta-v2`, producing readable folders such as `black-basta-v2-run001`. Existing runs are skipped; concurrent runs reserve different names. Names may be reused if old run folders are deleted. Folder names do not randomize the generated data.

This exercise covers the selected May publication tables plus the retained November set. It is a deliberately broad historical matching fixture, not one documented victim timeline. **Exact agreement with your converted STIX CSV has not been established.** See the [v2 source and coverage notes](examples/aa24-131a-black-basta-v2-notes.md).

## 4. Use only the event files in Splunk

Your local generation is complete once the count and coverage checks pass. Keep the printed output path. If you reopen PowerShell, set `$outputDir` to that exact path before using the [README Splunk instructions](../README.md#5-use-the-output-in-splunk).

| Output | Use |
| --- | --- |
| `events/*.jsonl` | Ingest into the analyst index as `secdata:cim:json` |
| `context/` | Reference inventory; keep outside the analyst index |
| `truth/` | Private answer key; keep outside the analyst index |
| Manifest and IOC coverage report | Verify the run; keep outside the analyst index |

Install/configure `TA-sec-data-cim` at the Splunk parsing tier before ingest so JSON `time` becomes event time. Create the destination index first. Use a fresh index for an isolated 10,000-event check and do not ingest the same run twice. Search **All Time**: the events are dated November 2024, regardless of when you generate or upload them.

No S3 transfer is necessary for a local run. If Splunk is on another machine, transfer this verified output there before ingestion; storage location does not change the generation steps.

## If a step fails

| Symptom | Next action |
| --- | --- |
| `py -3.15` is unavailable | Install/repair the approved Python build and launcher, then open a new shell |
| `.venv` points at older or removed Python | Run step 2 to preserve and rebuild the environment |
| New scenario or checker is missing | Confirm you opened the folder containing `create_dataset.py`; if files are absent, obtain a current repository copy in a separate folder and preserve your old files |
| Output directory already exists | Rerun the complete step 3 block to choose a new directory |
| Coverage fails | Stop before ingest; inspect the report and confirm v2 scenario/catalog paths |
| Splunk has no events or an unexpected count | Confirm the index exists, search All Time, check parsing and compare with this run's manifest |

For a different story, follow [scenario authoring](scenario-authoring.md). Omitting `--scenario-file` runs the built-in reference investigation; using the unsuffixed Black Basta JSON runs v1. Neither substitutes for this v2 coverage exercise.
