# sec-data

Generate synthetic security events for Splunk investigations and detection tests. The primary command combines a fixed, linked investigation with repeatable background activity and publishes one CIM-shaped JSONL event package. Generation runs locally and requires no Splunk instance, AWS account, or network scan.

| Task | Entry point | Result |
| --- | --- | --- |
| Generate events for Splunk | `create_dataset.py` | `events/` for ingest, `context/` for reference, and `truth/` for validation |
| Inspect the source story | `create_story.py` | Source-format observations, shared world data, timeline, and answer key |
| Export standalone findings | `create_vuln_table.py`, `create_compliance_table.py` | JSON or JSONL for local analysis or the optional AWS uploader |

The seed changes reproducible details, not the investigation plot. This release does not accept a natural-language story prompt or a scenario specification. See the [documentation index](docs/README.md) for the main workflow and source-format references.

## Quick start: generate a dataset

The examples use Windows PowerShell. Install Python 3.12 and Git; see the [Windows setup guide](docs/windows-software-requirements.md). The generator itself uses the Python standard library and is also tested in Linux CI.

```powershell
git clone https://github.com/garrettds11/sec-data.git C:\GitHub\sec-data
cd C:\GitHub\sec-data
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe .\create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --target-events 10000 --output-dir .\output\dataset-42
```

Choose an output directory that does not already exist. This command writes **exactly 10,000 events**. Change the seed or UTC start time for another repeatable run. `--target-events` changes the published count; 274 is the minimum for the one-campaign example shown here. More campaigns may require a higher minimum.

Inspect the result:

```powershell
Get-ChildItem .\output\dataset-42\events\*.jsonl
Get-Content .\output\dataset-42\events\recon.jsonl -TotalCount 2
Get-Content .\output\dataset-42\dataset-manifest.json
```

Generated runs under `output/` and the local `.venv/` are ignored by Git. After using a run, remove its directory to reclaim space. Keep `output/reference/` if you downloaded add-ons there for local inspection.

| Path in the output directory | What it contains | Index as security events? |
| --- | --- | --- |
| `events/*.jsonl` | CIM-shaped DNS, authentication, network, web, endpoint, file-access, and vulnerability observations | Yes |
| `context/` | Assets, external entities, relationships, policies, compliance assessments, and detection rules | No |
| `truth/` | Generator answer key, timeline, and expected alert and case outcomes | No |
| `dataset-manifest.json` | Run ID, exact counts, exclusions, byte sizes, and SHA-256 hashes | No |

The planted story and background activity share inventory, time range, CIM field names, and value types. Background DNS, authentication, connection, and HTTP records share session IDs. The command creates source observations temporarily to validate the story, then publishes the selected CIM-shaped events. Splunk searches can generate alerts or risk events; the generator's expected alerts and case actions remain in `truth/`.

## Use the events in Splunk

Install the official [Splunk Common Information Model add-on](https://splunkbase.splunk.com/app/1621) separately. This project was tested with version 8.7.0. For a local Windows Splunk installation, copy this repository's [TA-sec-data-cim add-on](splunk/TA-sec-data-cim/) into Splunk's apps directory from an elevated PowerShell, then restart Splunk:

```powershell
Copy-Item .\splunk\TA-sec-data-cim 'C:\Program Files\Splunk\etc\apps' -Recurse -Force
splunk restart
```

Create or choose a test index, then ingest **only** `events/*.jsonl` with sourcetype `secdata:cim:json`. With `splunk` on your PATH:

```powershell
$indexName = 'sec_data' # Change to your test index
Get-ChildItem .\output\dataset-42\events\*.jsonl | ForEach-Object {
    splunk add oneshot $_.FullName -index $indexName -sourcetype secdata:cim:json
}
```

Search **All Time** when checking the example run, because its event time is fixed in October 2026:

```spl
index=sec_data sourcetype=secdata:cim:json
| stats count by sec_data_cim_dataset
```

Splunk assigns `host`, `source`, `sourcetype`, `index`, and `splunk_server` at ingest; the JSON supplies the modeled observation fields and UTC `time`. The project add-on handles event boundaries, field extraction, event types, tags, and DNS arrays. The [lab report](docs/splunk-validation.md) records checks on the planted fixture in Splunk Enterprise 10.4.0 with CIM 8.7.0. The high-volume background stream has not undergone that live validation.

For an example of the index, sourcetype, and source values to expect after upload, see the [post-ingest source inventory](docs/dataset.md#expected-source-inventory-in-splunk).

## Choose a volume

`--target-events` sets an exact published count. The example 10,000-event run has 274 planted events and 9,726 background events, with roughly 2,400 background records in each of four event families. For a million-event run, use a new directory:

```powershell
.\.venv\Scripts\python.exe .\create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --target-events 1000000 --output-dir .\output\dataset-1m
```

An actual 100,000-event package contained 42.5 MB of event JSONL. A million-event run with the same mix is estimated near 425 MB; read the actual `events/` byte totals in its manifest before ingesting it against a 500 MB/day Splunk license. The million-event iterator was checked, while a full million-event file write and Splunk ingest have not been measured. See the [scale guide](docs/scale.md) for measured results and standalone finding options.

### Time coverage

The example uses `--start-time 2026-10-22T12:00:00Z` and the default `--duration-minutes 60`. Background events occupy **12:00–13:00 UTC** on October 22, excluding the end of that interval. The baseline assessment occurs at **11:59 UTC**, and the last planted event at **12:47:55 UTC**. The complete 10,000-event package spans **11:59:00–12:59:59.629 UTC**. Increasing `--target-events` makes events denser within the same interval. Set `--duration-minutes 240` for a four-hour window; this also spaces the planted operations farther apart. Each JSON event includes its own UTC timestamp for Splunk event-time extraction.

### Reproduce a released run

To use this version later, check out the release tag before generating data:

```powershell
git fetch --tags
git checkout v0.1.0
```

Record the tag, seed, UTC start time, duration, campaign count, host count, and target event count with the output. The `dataset-manifest.json` file records run parameters and hashes for every published file. Use those hashes to verify a regenerated package. Standalone finding exports also need an explicit `--as-of` or `--snapshots` value for repeatable assessment dates.

## Other commands

The standalone vulnerability and compliance commands retain their JSON and JSONL outputs for the optional AWS uploader. They are separate from the CIM event package. Specify `--as-of` when you need repeatable assessment dates; `--target-records` requests an exact applicable finding count or fails if the selected inventory and catalogs cannot supply it.

```powershell
.\.venv\Scripts\python.exe .\create_vuln_table.py --seed 42 --as-of 2026-10-22T12:00:00Z --host-count 3000 --target-records 10000 --format jsonl --output .\output\vuln-10k.jsonl
.\.venv\Scripts\python.exe .\create_compliance_table.py --seed 42 --as-of 2026-10-22T12:00:00Z --host-count 3000 --format jsonl --output .\output\compliance.jsonl
```

`create_story.py` builds the source story used internally and in the checked-in [reference fixture](tests/fixtures/README.md). `create_recon_events.py` and `create_cim_events.py` remain available for source-format experiments and projection of existing bundles. Use `create_dataset.py` for the single CIM-shaped analyst event package.

Run the checks locally:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

For field decisions, output layout, and investigation limits, read the [dataset guide](docs/dataset.md), [CIM guide](docs/cim.md), and [story guide](docs/story.md).

## Limits and optional upload

All records are synthetic. The generated Zeek-shaped and Windows-shaped reference files are not exact vendor raw events, and the project does not scan systems or provide official CIS Benchmark content. Five source observations and one TLS metadata observation lack a sound CIM mapping in the current dataset. The planted read and later upload support a correlation exercise; they do not prove which file bytes were transferred.

Only the separate [AWS uploader](upload_to_aws.py) contacts AWS. It accepts the standalone vulnerability and compliance outputs, requires `boto3` and configured credentials, and may create or upsert DynamoDB items with associated cost. For example, after generating `vuln-10k.jsonl`:

```powershell
.\.venv\Scripts\python.exe -m pip install boto3
.\.venv\Scripts\python.exe .\upload_to_aws.py --dataset vuln --input .\output\vuln-10k.jsonl --region us-east-1
```

The uploader prompts for a profile when one is not supplied and requires an explicit `UPLOAD` confirmation before writing. See the [Windows work instructions](docs/work-instructions-windows-vscode.md) for credentials and table details.

## License

See [LICENSE](LICENSE) and the [release notes](CHANGELOG.md).
