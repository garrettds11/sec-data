# sec-data

Generate synthetic security events for Splunk investigations and detection tests. The primary command combines a linked investigation with repeatable ordinary activity and publishes one CIM-shaped JSONL event package. Use the included reference story or supply a versioned scenario file for a tailored compromise. Generation runs locally and requires no Splunk instance, AWS account, or network scan.

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

To **run without AI**, follow the quick start below for the reference story or use the [manual workflow](docs/scenario-authoring.md) for a custom input. To **author with AI**, follow [AI authoring](docs/ai-authoring.md), including the attachment checklist for chats without checkout access. Both paths converge on validation, generation and the same Splunk ingest instructions.

Generic AI prompt (defaults to an AI-generated plausible story):

~~~text
create a threat story and generate synthetic data using the capabilities provide by this repo, https://github.com/garrettds11/sec-data
~~~

CISA-focused AI prompt (replace [ID]):

~~~text
create a threat story and generate synthetic data using one scenario JSON file based on CISA advisory [ID]. Follow the repo’s current scenario contract. Preserve documented facts, identify fictional additions separately, and propose the ordered story steps before generating data. Explain any details the current generator cannot represent. Details from the CISA publication should be used, including the IOCs, tactics, techniques, software, and weaknesses.
~~~

A repository-aware agent should read AGENTS.md, propose steps/settings and wait for your approval before generating a dataset. An ordinary chat needs the contract, example and inventory/field references attached; a local clone is not automatically visible to it. A CISA catalog row helps select a publication but does not replace its full text and revision. See the [Black Basta worked example](docs/examples/aa24-131a-black-basta-notes.md).

## Quick start: generate a dataset

The examples use Windows PowerShell. Install the latest patched Python 3.15 release and Git; see the [Windows setup guide](docs/windows-software-requirements.md). The generator itself uses the Python standard library. CI covers Python 3.12 and 3.15 on Windows and Linux; 3.15 is the default for new environments. See the [Python transition guide](docs/python-version.md) to migrate an existing virtual environment.

```powershell
$repoDir = 'C:\GitHub\sec-data'
git clone https://github.com/garrettds11/sec-data.git $repoDir
Set-Location $repoDir
py -3.15 -m venv .venv

$python = '.\.venv\Scripts\python.exe'
$seed = 42
$startTime = '2026-10-22T12:00:00Z'
$durationMinutes = 60
$targetEvents = 10000
$outputDir = '.\output\reference-investigation'

& $python .\create_dataset.py --seed $seed --start-time $startTime `
  --duration-minutes $durationMinutes --target-events $targetEvents `
  --output-dir $outputDir
```

Set `$seed` and `$startTime` for the run you want. Choose a descriptive `$outputDir` that does not already exist. Its name does not affect the generated events or manifest run ID, although Splunk will show the path as `source` after ingest. This command writes exactly `$targetEvents` events; see the [dataset guide](docs/dataset.md) for the reference run's planted count and source breakdown.

Inspect the result:

```powershell
Get-ChildItem -LiteralPath (Join-Path $outputDir 'events') -Filter '*.jsonl'
Get-Content -LiteralPath (Join-Path $outputDir 'events\web-app.jsonl') -TotalCount 2
Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json')
```

Generated runs under `output/` and the local `.venv/` are ignored by Git. After using a run, remove its directory to reclaim space. Keep `output/reference/` if you downloaded add-ons there for local inspection.

| Path in the output directory | What it contains | Index as security events? |
| --- | --- | --- |
| `events/*.jsonl` | CIM-shaped DNS, authentication, network, web, endpoint, file-access, and vulnerability observations | Yes |
| `context/` | Shared assets, external entities, identities, and relationships; reference-mode policies and assessments | No |
| `truth/` | Private story steps and causal links; reference-mode expected alerts and case outcomes | No |
| `dataset-manifest.json` | Run ID, exact counts, exclusions, byte sizes, and SHA-256 hashes | No |

The planted story and ordinary activity share inventory, time range, CIM field names, and value types. DNS, authentication, network, web, endpoint, and file observations form linked routine sessions. Story events are merged into the corresponding source files in event-time order; there is no separate background source. The fixed story is built and validated privately before publishing its CIM projection. Splunk searches can generate alerts or risk events; the generator's expected alerts and case actions remain in `truth/`.

### Tailored scenario

To author a tailored scenario, copy [the example](scenarios/file-collection.json), edit its ordered steps and inventory references, then reuse the variables from the quick start above:

```powershell
$scenarioFile = '.\scenarios\file-collection.json'
$outputDir = '.\output\file-collection'
& $python .\validate_scenario.py --scenario-file $scenarioFile `
  --seed $seed --duration-minutes $durationMinutes --target-events $targetEvents
& $python .\create_dataset.py --seed $seed --start-time $startTime `
  --duration-minutes $durationMinutes --target-events $targetEvents `
  --scenario-file $scenarioFile --output-dir $outputDir
```

The validator writes no event package and reports prescribed counts and minimum duration. A valid result establishes structural compatibility, not source fidelity or causal plausibility. For supported fields and seeded assets, use `validate_scenario.py --describe-contract` and `--describe-context --seed 42 --host-count 23`.

The tailored mode builds the shared world directly and writes only its authored story plus ordinary traffic. Its title, causal links, and step descriptions appear in `truth/scenario-truth.json`, never in analyst events. The [scenario guide](docs/scenarios.md) defines supported sources, fields, references, and validation.

## Use the events in Splunk

Install the official [Splunk Common Information Model add-on](https://splunkbase.splunk.com/app/1621) separately. This project was tested with version 8.7.0. For a local Windows Splunk installation, copy this repository's [TA-sec-data-cim add-on](splunk/TA-sec-data-cim/) into Splunk's apps directory from an elevated PowerShell, then restart Splunk:

```powershell
Copy-Item .\splunk\TA-sec-data-cim 'C:\Program Files\Splunk\etc\apps' -Recurse -Force
splunk restart
```

Create the `sec_data` index before ingesting: in Splunk Web, select **Settings → Indexes → New Index**, or run `splunk add index sec_data` once from the CLI. Splunk can report that `add oneshot` queued a file even when it later drops the events because the index does not exist. Ingest **only** `events/*.jsonl` with sourcetype `secdata:cim:json`. The following uses the current `$outputDir` from the generation block; set it to the run you want if you opened a new PowerShell session. With `splunk` on your PATH:

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

To inspect the example run by CIM dataset, search **All Time** because its event time is fixed in October 2026:

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
$outputDir = '.\output\reference-volume-1m'
& $python .\create_dataset.py --seed $seed --start-time $startTime `
  --duration-minutes $durationMinutes --target-events $targetEvents `
  --output-dir $outputDir
```

A million-event package may approach a 500 MB/day Splunk license limit; read the actual `events/` byte totals in its manifest before ingest. A full million-event export and live Splunk ingest have not yet been measured for this design. See the [scale guide](docs/scale.md) for measurement details.

### Time coverage

`$startTime` and `$durationMinutes` define the routine-event window. The reference story also includes a baseline assessment before that window. Increasing `$targetEvents` makes events denser within the same interval; set `$durationMinutes = 240` for a four-hour window that also spaces the planted operations farther apart. Each JSON event includes its own UTC timestamp for Splunk event-time extraction. The [dataset guide](docs/dataset.md#time-scale-and-interpretation) records the measured time span of the reference run.

### Reproduce a released run

To reproduce the v0.1.0 release later, check out its tag before generating data:

```powershell
git fetch --tags
git checkout v0.1.0
```

Record the tag, seed, UTC start time, duration, campaign count, host count, and target event count with the output. The `dataset-manifest.json` file records run parameters and hashes for every published file. Use those hashes to verify a regenerated package. Standalone finding exports also need an explicit `--as-of` or `--snapshots` value for repeatable assessment dates.

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
