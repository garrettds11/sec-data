# Author a tailored investigation

`create_dataset.py` accepts a versioned JSON scenario. A person or LLM can write this file, and the existing generator turns it into the same CIM-shaped, source-specific event package as the reference investigation. Changing the plot, timing, assets, external destinations, and ordinary traffic mix does not require editing generator code.

Start with [`scenarios/file-collection.json`](../scenarios/file-collection.json). It models an inbound request, use of an operator account, process execution, a file read, an outbound connection, and a later block. The file describes seven planted observations in six ordered steps; `--target-events` fills the rest of the requested count with ordinary activity. The [README tailored-scenario command](../README.md#tailored-scenario) shows the named PowerShell variables and generator invocation. Choose a new `$outputDir` for each run.

Index only `events/*.jsonl`. Use `context/` to look up assets, identities, and external entities. Keep `truth/scenario-truth.json` out of the analyst index: it contains the story title, causal links, step descriptions, and event IDs.

## Contract

The top-level JSON object requires `schema_version: 1`, a nonempty `id`, a `title`, and a nonempty `steps` array. It may include `description`, `entities`, and `background_mix`. Each step requires a unique `id`, `offset_seconds` from the run's `--start-time`, and one or more `observations`. Steps must appear in time order and stay inside `--duration-minutes`. Optional `depends_on` IDs must name earlier steps; optional step `description` appears only in truth.

Each observation requires `source`, `dataset`, and a `fields` object. An optional nonnegative `delay_ms` orders observations within a step. The generator adds `time`, `event_id`, `session_id`, `synthetic`, `sec_data_source`, and `sec_data_cim_dataset`. Those keys cannot be supplied in `fields`. Narrative or ground-truth flags are also rejected from analyst events.

Use a literal field value or an inventory reference:

```json
{"src": {"ref": "asset:prod-web-02:ip"},
 "user": {"ref": "identity:identity-operator-01:account"},
 "dest": {"ref": "entity:entity-transfer-destination:ip"}}
```

References use `asset:<short_name>:<field>`, `identity:<identity_id>:<field>`, or `entity:<entity_id>:<field>`. The generator resolves them against `context/` and rejects missing names or fields. Its base inventory includes `prod-web-02`, `prod-file-01`, `bastion-01`, `LAB\\operator`, and other named assets and identities. Custom external entities may be supplied as `{"entity_id": "...", "name": "...", "ip": "...", "role": "..."}` under `entities`; they are written to `context/entities.jsonl` and can then be referenced. Entity IPs must parse as IP addresses.

The current compiler accepts these source and CIM dataset combinations. The example shows field usage for six of them.

| Source file | CIM dataset |
| --- | --- |
| `resolver-dns.jsonl` | `Network_Resolution.DNS` |
| `web-auth.jsonl`, `windows-security.jsonl` | `Authentication.Authentication` |
| `eastwest-firewall.jsonl`, `perimeter-firewall.jsonl`, `ingress-firewall.jsonl`, `ingress-zeek-conn.jsonl`, `egress-firewall.jsonl`, `zeek-conn.jsonl`, `response-firewall.jsonl` | `Network_Traffic.All_Traffic` |
| `web-app.jsonl`, `edge-proxy.jsonl`, `ingress-zeek-http.jsonl`, `zeek-http.jsonl` | `Web.Web` |
| `endpoint-lab.jsonl`, `sysmon.jsonl` | `Endpoint.Processes` |
| `windows-file.jsonl` | `Data_Access.Data_Access` |
| `vulnerability.jsonl`, `vulnerability-followup.jsonl` | `Vulnerabilities.Vulnerabilities` |
| `sysmon.jsonl` | `Endpoint.Filesystem`, `Endpoint.Registry`, or `Network_Traffic.All_Traffic` |
| `windows-security.jsonl` | `Change.All_Changes` |

The compiler checks each source/dataset pair, required fields, field types, time bounds, references, and byte totals when all three byte fields are supplied. It rejects an unsupported combination instead of emitting an arbitrary event shape. This contract produces CIM-shaped JSON; it does not claim to reproduce exact vendor raw records or prove that all supplied observations are causally possible. Authors should review sensor coverage, protocol plausibility, identity privileges, and detection outcomes for each new story.

`background_mix` requires integer weights from 0 to 100 for `web`, `file`, `egress`, and `ingress`; at least one must be positive. The default is `{"web":5,"file":2,"egress":2,"ingress":1}`. Weights select whole linked sessions, then the generator distributes the requested event count across the time window. A final partial session is possible when the exact count is not divisible by session size. Scenario observations and ordinary records are merged by `time` into their respective source files. The run manifest reports both per-source counts and the planted/background split; the split is metadata, never an analyst event field.

## Using an LLM as the story author

Give the LLM this guide, the example scenario, and a clear investigation objective. Ask it to return only a schema-version-1 JSON file with the causal steps and sensor observations it expects an analyst to find. Review the proposed source/dataset pairs and run the command above. A validation error identifies an invalid source, field, reference, or time, so the file can be revised without changing Python code. Keep sensitive real-world names and addresses out of prompts and scenarios.

The fixed reference story remains available by omitting `--scenario-file`. `--campaign-count` applies only to that reference story. A tailored run generates its world directly and publishes only the authored steps plus ordinary traffic; it does not silently add the fixed compromise story or its expected alerts.
