# One CIM event dataset per run

`create_dataset.py` publishes one analyst-facing event representation. It builds and validates source observations in a private temporary directory, projects supported observations to CIM-shaped JSONL, then publishes only the selected event view. The temporary source records are removed after publication. Standalone vulnerability and compliance commands retain their current output contracts for the optional AWS uploader.

```powershell
python create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --target-events 10000 --output-dir .\output\dataset-42
```

The output directory must be new. The package contains:

| Directory | Contents | Splunk ingest? |
| --- | --- | --- |
| `events/` | CIM-shaped JSONL for DNS, traffic, web, authentication, account change, endpoint, file access, and vulnerabilities | Yes, with `secdata:cim:json` and the project add-on |
| `context/` | Assets, external entities, relationships, identities, policies, data objects, compliance assessments, and detection rule definitions | No; use as separate investigation context |
| `truth/` | Scenario timeline, causal links, sensor coverage, modeled state changes, and expected alert/case outcomes | No; this is the answer key |
| `dataset-manifest.json` | Run ID, event count, omissions, file sizes, and SHA-256 hashes | No |

For seed 42 and the default 60-minute run, the planted investigation contributes **274 records in 15 files across ten CIM datasets**. The earlier projection fixture had 291 records: this package omits eight duplicate DNS records from the second view and nine scripted alert/case records. The expected alert and case outcomes remain in `truth/` for comparing with Splunk detections; they are not preloaded as analyst events. Five source observations have no sound CIM mapping, and one TLS metadata observation is not yet mapped. The manifest records these omissions.

`--target-events` sets the **exact published count**, with a minimum of the linked story's 274 records. The default is 10,000. The difference is streamed into `events/background-session.jsonl` as ordinary benign sessions: DNS resolution, successful authentication, an allowed connection, and an HTTP GET share a session ID and assets from the run's inventory. Seed and start time make the sequence repeatable. A 10,000-event run has 9,726 background records, about 2,430 of each event family.

With the example start time of `2026-10-22T12:00:00Z` and the default 60-minute duration, background events fill `[12:00, 13:00)` UTC. The planted baseline starts at 11:59 and its last event is at 12:47:55. Consequently the default 10,000-event package spans 11:59:00–12:59:59.629 UTC; a measured 100,000-event package spans 11:59:00–12:59:59.963 UTC. `--target-events` changes density, while `--duration-minutes` changes the background time window.

The planted story and high-volume session generator are separate components. Both emit the same common event fields and use the same CIM dataset names, field types, and value directions. A regression check compares representative DNS, authentication, traffic, and web fields against the Splunk-validated story fixture. Source-specific optional fields may differ because the modeled observations differ.

## Expected source inventory in Splunk

The table below shows the expected source inventory after uploading the seed-42 dataset to `sec_data`. Each `events/*.jsonl` file becomes a separate `source` when uploaded with the README's `splunk add oneshot` loop. The path prefix reflects the local checkout and will differ on another machine. Splunk assigns the index and sourcetype at ingest; they are not fields in the generated JSON.

| index | sourcetype | source |
| --- | --- | --- |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\background-session.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\edge-proxy.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\egress-firewall.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\ingress-firewall.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\ingress-zeek-conn.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\ingress-zeek-http.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\recon.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\response-firewall.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\sysmon.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\vulnerability-followup.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\vulnerability.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\web-auth.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\windows-file.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\windows-security.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\zeek-conn.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\dataset-42\events\zeek-http.jsonl` |
| `sec_data` | `secdata:cim:json` | `C:\GitHub\sec-data\output\splunk-lab-upload-v4.jsonl` |

The last row appears only if the earlier combined lab fixture is also uploaded to `sec_data`; it is not a file from `create_dataset.py`. A fresh dataset-only ingest should show the 16 `events/` sources above. To check the source inventory in Splunk, set the time picker to **All Time** and run:

```spl
index=sec_data sourcetype=secdata:cim:json
| stats count by index sourcetype source
| sort source
```

If the earlier combined upload is still present, its events are additional copies of the planted story. Filter it out or use a clean index when checking the dataset's exact event count.

For a high-volume run:

```powershell
python create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --target-events 1000000 --output-dir .\output\dataset-1m
```

The background writer and file hashing stream records rather than loading the million-event file into memory. A count-only run yielded one million background records in 14.49 seconds on the local test machine; this excludes serialization and disk writes. An actual 100,000-event package completed with 100,000 JSONL rows and 42,520,967 event bytes; its background file matched the manifest hash. That suggests about 425 MB for a million events with the same mix. Actual size depends on the run and should be read from `dataset-manifest.json` before Splunk ingest, especially with a 500 MB/day license. The previous live Splunk checks used the planted fixture; background sessions need a separate ingest check before using them to assess high-volume search behavior.

The source observations remain the internal evidence used to construct and validate the story. No published event file claims to be exact Zeek, Windows, or Sysmon raw output. The planted CIM fields were tested in the [local Splunk lab](splunk-validation.md); the 274-record core is a selected subset of that 291-record fixture. The project add-on provides one-line JSON framing, UTC timestamp extraction, event types, tags, and DNS array aliases. The `sec_data_cim_dataset` field is a routing hint; Splunk data-model membership comes from the add-on's tags. The dataset is intended for investigation and detection testing, with Splunk searches free to produce their own alerts or risk events.
