# Set up variables
```
$repoDir = 'C:\code\GitHub\sec-data'
git clone https://github.com/garrettds11/sec-data.git $repoDir
Set-Location $repoDir
py -3.12 -m venv .venv
$python = '.\.venv\Scripts\python.exe'
$seed = 2
$startTime = '2024-11-12T08:00:00Z'
$durationMinutes = 120
$targetEvents = 10000
$scenarioFile = '.\scenarios\cisa\aa24-131a-black-basta.json'
$outputDir = '.\output\aa24-131a-black-basta'
```

# Validate without generating data.
```
& $python .\validate_scenario.py --scenario-file $scenarioFile `
  --seed $seed --duration-minutes $durationMinutes `
  --target-events $targetEvents

if ($LASTEXITCODE -ne 0) {
    throw 'Scenario validation failed.'
}
```

# Generate one complete dataset.
```
& $python .\create_dataset.py --seed $seed --start-time $startTime `
  --duration-minutes $durationMinutes --target-events $targetEvents `
  --scenario-file $scenarioFile --output-dir $outputDir

if ($LASTEXITCODE -ne 0) {
    throw 'Dataset generation failed.'
}
```
