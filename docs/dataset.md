# One CIM event dataset per run

`create_dataset.py` publishes CIM-shaped JSONL events for Splunk, a shared world catalog, and a separate answer key. The reference mode builds and validates the fixed source story privately, projects it to CIM fields, then adds linked routine sessions. With `--scenario-file`, it builds the world directly and compiles the authored steps instead. Both modes publish observations under `events/`, grouped by modeled source and sorted by event time.

Run the [README quick start](../README.md#quick-start-generate-a-dataset) for the canonical PowerShell example. It names the seed, start time, duration, event target, and output directory as variables. Change `$outputDir` for each run; the folder name has no generator semantics. The seed, UTC start, duration, inventory size, scenario, event target, and background mix determine the run. The manifest records file hashes and counts. For a tailored story, read the [scenario contract](scenarios.md) and add `--scenario-file`.

| Directory | Contents | Index as security events? |
| --- | --- | --- |
| `events/` | CIM-shaped observations, one JSONL file per modeled sensor or source | Yes, with `secdata:cim:json` and the project add-on |
| `context/` | Assets, entities, identities, and relationships; the reference mode also includes policies, data objects, compliance, and detection rules | No |
| `truth/` | Private story steps and causal links; the reference mode also includes expected alerts and case outcomes | No |
| `dataset-manifest.json` | Run parameters, counts, omissions, bytes, and SHA-256 hashes | No |

The reference one-campaign run contributes 274 planted CIM observations. The earlier projection fixture contains 291: this package omits eight duplicate DNS records and nine scripted alert or case outcomes. Five source observations have no sound CIM projection, and one TLS metadata observation is not mapped. The manifest records these exclusions. A tailored scenario includes only its authored observations and routine activity, with no fixed-story events.

`--target-events` is an exact published count and must be at least the planted count. The default is 10,000. The reference example therefore adds 9,726 routine observations. The default mix uses linked web, file, egress, and ingress sessions. DNS, authentication, traffic, web, process, and file observations share session IDs where they describe one modeled activity. Some cross-sensor views intentionally describe the same connection. A final partial session is possible when an exact target cuts across a session boundary.

## Expected source inventory in Splunk

The table is a measured snapshot of the [README reference configuration](../README.md#quick-start-generate-a-dataset): seed 42, 23 hosts, one campaign, a one-hour duration, and the default background mix. Seed 42 identifies the reproducible fixture; it does not determine the output folder name. Counts change with other parameters or scenarios. Uploading each file with the README's `splunk add oneshot` loop makes its path the Splunk `source`. The prefix is your checkout path; the final file name is stable. Splunk assigns `index` and `sourcetype` at ingest. This example uses `sec_data` and `secdata:cim:json`.

| index | sourcetype | source filename | events |
| --- | --- | --- | ---: |
| `sec_data` | `secdata:cim:json` | `eastwest-firewall.jsonl` | 1,399 |
| `sec_data` | `secdata:cim:json` | `edge-proxy.jsonl` | 273 |
| `sec_data` | `secdata:cim:json` | `egress-firewall.jsonl` | 544 |
| `sec_data` | `secdata:cim:json` | `endpoint-lab.jsonl` | 3 |
| `sec_data` | `secdata:cim:json` | `ingress-firewall.jsonl` | 274 |
| `sec_data` | `secdata:cim:json` | `ingress-zeek-conn.jsonl` | 273 |
| `sec_data` | `secdata:cim:json` | `ingress-zeek-http.jsonl` | 272 |
| `sec_data` | `secdata:cim:json` | `perimeter-firewall.jsonl` | 14 |
| `sec_data` | `secdata:cim:json` | `resolver-dns.jsonl` | 1,360 |
| `sec_data` | `secdata:cim:json` | `response-firewall.jsonl` | 1 |
| `sec_data` | `secdata:cim:json` | `sysmon.jsonl` | 556 |
| `sec_data` | `secdata:cim:json` | `vulnerability-followup.jsonl` | 68 |
| `sec_data` | `secdata:cim:json` | `vulnerability.jsonl` | 68 |
| `sec_data` | `secdata:cim:json` | `web-app.jsonl` | 1,363 |
| `sec_data` | `secdata:cim:json` | `web-auth.jsonl` | 1,357 |
| `sec_data` | `secdata:cim:json` | `windows-file.jsonl` | 543 |
| `sec_data` | `secdata:cim:json` | `windows-security.jsonl` | 546 |
| `sec_data` | `secdata:cim:json` | `zeek-conn.jsonl` | 543 |
| `sec_data` | `secdata:cim:json` | `zeek-http.jsonl` | 543 |

The small endpoint-lab, perimeter, response, and vulnerability streams reflect event types whose frequency is tied to the reference story or assessment schedule. They should not be interpreted as independently calibrated, enterprise-scale source volumes. A tailored scenario can put its observations in any supported source from the [scenario guide](scenarios.md). Use the manifest's `source_counts` and `origin_counts` to inspect the actual distribution before ingest.

Check a newly indexed run with the Splunk time picker set to **All Time**:

```spl
index=sec_data sourcetype=secdata:cim:json
| stats count by index sourcetype source
| sort source
```

If the same events were indexed before, the search includes duplicates. Use a fresh index or filter by the new source path when comparing counts to a manifest. The screenshot in the [Splunk lab report](splunk-validation.md) shows an earlier validation upload and uses the old `sec_data_lab` index; it remains a historical lab artifact.

## Time, scale, and interpretation

With `--start-time 2026-10-22T12:00:00Z` and the default 60-minute duration, routine events occupy `[12:00, 13:00)` UTC. The fixed baseline assessment occurs at 11:59 UTC, and its last planted event is at 12:47:55 UTC. The complete 10,000-event reference package spans 11:59:00–12:59:59.629 UTC. Use `--duration-minutes 240` for a four-hour background window and a more spacious planted timeline. The background scheduler is even across the window; it does not model a daily business cycle.

A current 10,000-event reference package contained 4,295,193 event bytes. A million-event run may approach the 500 MB/day license limit, so inspect the actual `events/` byte total in its manifest before indexing. The writer spools by source and merges in bounded memory. A full million-event export and Splunk ingest have not been measured for this design.

These are CIM-shaped observations, not exact vendor raw messages. The local [Splunk validation](splunk-validation.md) established field extraction and tagging for the earlier planted fixture; the expanded source streams and authored scenario mode still require a live ingest check. `sec_data_cim_dataset` is an event routing hint; data-model membership depends on the project add-on's event types and tags. The generator's narrative and expected outcomes stay in `truth/`; Splunk searches remain free to create their own alerts or risk events.
