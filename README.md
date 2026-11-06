# sec-data

Generate synthetic security events for Splunk investigations and detection tests. A run combines a planted investigation with repeatable background activity, then writes one CIM-shaped JSONL view for analyst ingest. It runs locally; generating data does not require Splunk, AWS, or a network scan.

## Quick start: generate a dataset

Requirements: Windows 10/11, Python 3.12, PowerShell, and Git. See the [Windows setup guide](docs/windows-software-requirements.md) for tooling details.

```powershell
git clone https://github.com/garrettds11/sec-data.git C:\code\Github\sec-data
cd C:\code\Github\sec-data
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe .\create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --target-events 10000 --output-dir .\output\dataset-42
```

Choose an output directory that does not already exist. The command writes **exactly 10,000 events**. Use another seed or UTC start time for a different run. For a larger file set, change `--target-events`; the minimum is the 274-event planted story, and the default is 10,000.

Inspect the result:

```powershell
Get-ChildItem .\output\dataset-42\events\*.jsonl
Get-Content .\output\dataset-42\events\recon.jsonl -TotalCount 2
Get-Content .\output\dataset-42\dataset-manifest.json
```

Generated runs under `output/` and the local `.venv/` are ignored by Git. After using a run, remove its output directory to reclaim space; keep `output/reference/` if you downloaded add-ons there for local inspection.

| Path in the output directory | What it contains | Index as security events? |
| --- | --- | --- |
| `events/*.jsonl` | CIM-shaped DNS, authentication, network, web, endpoint, file-access, and vulnerability observations | Yes |
| `context/` | Assets, external entities, relationships, policies, compliance assessments, and detection rules | No |
| `truth/` | Generator answer key, timeline, and expected alert and case outcomes | No |
| `dataset-manifest.json` | Run ID, exact counts, exclusions, byte sizes, and SHA-256 hashes | No |

The planted story and background activity share inventory, time range, CIM field names, and value types. Background DNS, authentication, connection, and HTTP records share session IDs. The script creates source observations privately to validate the story, then publishes only the CIM-shaped analyst events. Splunk searches can produce their own alerts or risk events; the generator's expected alerts and case actions stay in `truth/`.

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

Splunk assigns `host`, `source`, `sourcetype`, `index`, and `splunk_server` at ingest; the JSON supplies the modeled observation fields and UTC `time`. The add-on handles line boundaries, field extraction, event types, tags, and DNS arrays. The [lab report](docs/splunk-validation.md) shows searches and observed results from Splunk Enterprise 10.4.0 with CIM 8.7.0. The new background volume has not been indexed in that lab test.

For an example of the index, sourcetype, and source values to expect after upload, see the [post-ingest source inventory](docs/dataset.md#expected-source-inventory-in-splunk).

## Choose a volume

`--target-events` sets an exact published count. The default 10,000-event run has 274 planted events and 9,726 background events, with roughly 2,400 background records in each of four event families. For a million-event run, use a new directory:

```powershell
.\.venv\Scripts\python.exe .\create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --target-events 1000000 --output-dir .\output\dataset-1m
```

An actual 100,000-event package contained 42.5 MB of event JSONL. A million-event run with the same mix is estimated near 425 MB; read the actual `events/` byte totals in its manifest before ingesting it against a 500 MB/day Splunk license. The million-event iterator was checked, while a full million-event file write and Splunk ingest have not been measured. See the [scale guide](docs/scale.md) for measured results and standalone finding options.

### Time coverage

The example uses `--start-time 2026-10-22T12:00:00Z` and the default `--duration-minutes 60`. Background events are spread from **12:00 UTC up to, but before, 13:00 UTC** on October 22. The planted baseline assessment is at **11:59 UTC**, one minute before the start; its last event is at **12:47:55 UTC**. Thus the complete default 10,000-event output spans **11:59:00 through 12:59:59.629 UTC**. The measured 100,000-event output ends at **12:59:59.963 UTC**. Increasing `--target-events` makes events denser within the same window; change `--duration-minutes` to cover a longer or shorter period.

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

See [LICENSE](LICENSE).
