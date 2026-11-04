# One CIM event dataset per run

`create_dataset.py` publishes one analyst-facing event representation. It builds and validates source observations in a private temporary directory, projects supported observations to CIM-shaped JSONL, then publishes only the selected event view. The temporary source records are removed after publication. Standalone vulnerability and compliance commands retain their current output contracts for the optional AWS uploader.

```powershell
python create_dataset.py --seed 42 --start-time 2026-10-22T12:00:00Z --output-dir .\output\dataset-42
```

The output directory must be new. The package contains:

| Directory | Contents | Splunk ingest? |
| --- | --- | --- |
| `events/` | CIM-shaped JSONL for DNS, traffic, web, authentication, account change, endpoint, file access, and vulnerabilities | Yes, with `secdata:cim:json` and the project add-on |
| `context/` | Assets, external entities, relationships, identities, policies, data objects, compliance assessments, and detection rule definitions | No; use as separate investigation context |
| `truth/` | Scenario timeline, causal links, sensor coverage, modeled state changes, and expected alert/case outcomes | No; this is the answer key |
| `dataset-manifest.json` | Run ID, event count, omissions, file sizes, and SHA-256 hashes | No |

For seed 42 and the default 60-minute run, `events/` has **274 records in 15 files across ten CIM datasets**. The earlier projection fixture had 291 records: this package omits eight duplicate DNS records from the second view and nine scripted alert/case records. The expected alert and case outcomes remain in `truth/` for comparing with Splunk detections; they are not preloaded as analyst events. Five source observations have no sound CIM mapping, and one TLS metadata observation is not yet mapped. The manifest records these omissions.

The source observations remain the internal evidence used to construct and validate the story. No published event file claims to be exact Zeek, Windows, or Sysmon raw output. The CIM fields were tested in the [local Splunk lab](splunk-validation.md); the 274-record package is a selected subset of that 291-record fixture. The project add-on provides one-line JSON framing, UTC timestamp extraction, event types, tags, and DNS array aliases. The `sec_data_cim_dataset` field is a routing hint; Splunk data-model membership comes from the add-on's tags. The dataset is intended for investigation and detection testing, with Splunk searches free to produce their own alerts or risk events.
