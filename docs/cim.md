# CIM-shaped synthetic observations

`create_cim_events.py` creates separate JSONL files with Splunk CIM field names. It reads the existing synthetic observations without changing their source files or scenario truth. Its mapping reference is Splunk CIM **8.8**. The project-owned `splunk/TA-sec-data-cim` add-on supplies a synthetic sourcetype, JSON and timestamp extraction, event types, tags, and global visibility. No live Splunk validation is claimed.

## Generate

PowerShell, from the repository root:

```powershell
python create_story.py --seed 42 --start-time 2026-10-22T12:00:00Z --output-dir .\output\story-42 --cim-output-dir .\output\story-42-cim
```

For a story already on disk:

```powershell
python create_cim_events.py --story-dir .\output\story-42 --output-dir .\output\story-42-cim
```

For standalone vulnerability or recon output, generate JSONL first, then project it:

```powershell
python create_vuln_table.py --seed 42 --as-of 2026-10-22T12:00:00Z --format jsonl --output .\output\vulnerability.jsonl
python create_cim_events.py --input-file .\output\vulnerability.jsonl --source vulnerability.jsonl --output-file .\output\vulnerability.cim.jsonl
python create_recon_events.py --start-time 2026-10-22T12:00:00Z --output .\output\recon.jsonl --truth-output .\output\recon-truth.json
python create_cim_events.py --input-file .\output\recon.jsonl --source recon.jsonl --output-file .\output\recon.cim.jsonl
```

The story projection creates one `.cim.jsonl` file per observed source and a `cim-manifest.json` with source and output checksums, counts, unmapped counts, and validation status. All output paths must be new.

## Mapping coverage

| Source | Target CIM dataset | Notes |
| --- | --- | --- |
| `recon.jsonl` | DNS, Network Traffic, Web, Endpoint Processes | Service-query subtype stays unmapped. |
| `dns.log` | Network Resolution DNS | A second view of recon DNS; index either view if duplicate transactions are unwanted. |
| ingress/egress/response firewall and Zeek conn | Network Traffic | Original and responding byte directions follow the observing device. |
| Zeek HTTP and edge proxy | Web | URLs retain host and URI; no unseen scheme is invented. |
| web auth and Windows Security | Authentication; one account change | Web account lockout event stays unmapped. |
| Sysmon | Endpoint Processes, Filesystem, Registry; Network Traffic | Process and file actions come from the Sysmon event code. |
| Windows file audit | Data Access | Share path is assembled from the observed local share path and relative target. |
| vulnerability baseline/follow-up | Vulnerabilities | Only actual CVE IDs populate `cve`; scanner-only plugins still have a signature. |
| alerts and case actions | Alerts and TicketManagement | Describes detector output and case history, not raw activity. |

Inventory, entities, identities, policies, compliance assessment snapshots, timeline, state changes, and truth manifests remain outside the CIM event projection. A compliance snapshot has no direct event mapping here; the status remains available in the source bundle for context.

Each row includes `time`, `synthetic`, `sec_data_source`, and `sec_data_cim_dataset`. The last field is project metadata for routing and audit; it does **not** cause Splunk data-model membership. `tag` is intentionally absent because Splunk generates that field through its knowledge objects. Source timestamps are preserved as ISO UTC strings; DNS and Zeek epoch timestamps are rendered in UTC. DNS response times and recon durations are in seconds. The projection does not imply that these concise events match vendor raw formats or that vendor add-ons will parse them.

## Splunk add-on

Install `splunk/TA-sec-data-cim` as one app on the appropriate Splunk parsing and search tiers. Assign **`secdata:cim:json`** as the sourcetype for the `.cim.jsonl` files in your input or HEC configuration and choose the target index there. Keep the input's `source` as its file or stream identity. Splunk supplies `host`, `source`, `sourcetype`, `index`, and `splunk_server`; the assigned `host` may identify the forwarder or ingesting machine rather than the endpoint described in `src`, `dest`, or `dvc`. Do not set a vendor sourcetype to inherit a vendor add-on's parsing or tags.

The add-on uses `props.conf` for one-line JSON and UTC millisecond timestamps, `eventtypes.conf` to select the twelve projected datasets by `sec_data_cim_dataset`, `tags.conf` for their CIM tags, and `metadata/default.meta` to expose the knowledge objects to the CIM app. One app handles all generated sources because they share a JSON structure; `sec_data_source` retains each originating generator view. If a future source needs a distinct parser, it can get its own project-owned sourcetype in this add-on. The add-on does not create an input or choose an index because those are deployment-specific.

Before declaring the data CIM compliant in Splunk, ingest a deterministic fixture with this add-on and verify `_time`, JSON extraction, event types, tags, and representative events in each intended data model. Compare source and projected counts using the manifest and inspect field values, especially action and byte direction. Pin the Splunk platform and CIM add-on versions during that live test. Splunk documentation: [CIM DNS](https://help.splunk.com/en/data-management/common-information-model/8.8/data-models/network-resolution-dns), [CIM Network Traffic](https://help.splunk.com/en/data-management/common-information-model/8.8/data-models/network-traffic), [CIM Vulnerabilities](https://help.splunk.com/en/data-management/common-information-model/8.8/data-models/vulnerabilities), [event types and tags](https://help.splunk.com/en/splunk-cloud-platform/manage-knowledge-objects/knowledge-management-manual/10.5.2605/event-types/about-event-types).
