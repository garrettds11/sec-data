$ErrorActionPreference = 'Stop'

$seed = 2
$startTime = '2024-11-12T08:00:00Z'
$durationMinutes = 120
$targetEvents = 10000
$hostCount = 23
$scenarioFile = '.\scenarios\cisa\aa24-131a-black-basta-v2.json'
$coverageFile = '.\catalogs\intelligence\aa24-131a-publication-coverage-v2.json'
$outputRoot = '.\output'

python .\validate_scenario.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount `
    --duration-minutes $durationMinutes --target-events $targetEvents
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed.' }

$runJson = python .\create_dataset.py --scenario-file $scenarioFile `
    --seed $seed --host-count $hostCount --start-time $startTime `
    --duration-minutes $durationMinutes --target-events $targetEvents `
    --output-root $outputRoot --json
if ($LASTEXITCODE -ne 0) { throw 'Dataset generation failed.' }
$outputDir = ($runJson | ConvertFrom-Json).output_dir

python .\validate_ioc_coverage.py --dataset-dir $outputDir `
    --coverage-file $coverageFile `
    --output (Join-Path $outputDir 'ioc-coverage-report.json')
if ($LASTEXITCODE -ne 0) { throw 'Publication indicator coverage failed.' }

$manifest = Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.event_records -ne $targetEvents) { throw 'Unexpected event count.' }
Write-Host "Verified $($manifest.event_records) events in $outputDir"
Get-ChildItem -LiteralPath (Join-Path $outputDir 'events') -Filter '*.jsonl' -File
