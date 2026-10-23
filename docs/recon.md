# Offline reconnaissance telemetry

`create_recon_events.py` uses the default 23-host inventory in `common/assets.py`. It never scans a network, executes a tool, contacts a reference URL, or uses AWS. It builds four modeled operations per campaign set plus ordinary browsing sessions, then projects them into normalized sensor observations. The four families are external service discovery with web follow-up, internal service/share discovery, monitored Nmap-like SYN probing, and an approved scanner control. The web paths are inert strings; responses contain no secrets.

```powershell
python .\create_recon_events.py --seed 42 `
  --start-time 2026-10-22T12:00:00Z --duration-minutes 60 `
  --campaign-count 1 --output .\output\recon-events.jsonl `
  --truth-output .\output\recon-truth.json
python .\create_recon_events.py --seed 42 `
  --start-time 2026-10-22T12:00:00Z --no-endpoint `
  --no-http-sensor --nmap-indicator behavior-only --dry-run
```

`--campaign-count` is the number of four-family sets (1–100). `--duration-minutes` must allow four minutes per set. The default background model adds one internal browsing session per operation; `--background-sessions-per-minute` accepts 0–10 modeled sessions per minute and rounds to a whole-session count per operation. All rates, ports, results, delays, and target counts are project assumptions, **not observed incident or Nmap packet measurements**. Same seed, explicit start time, flags, and generator version produce byte-identical output. Events are sorted by occurrence time within each operation; `collected_at` may be later. Use `--dry-run` for counts without files.

## Event and truth schema

Every analyst-facing JSONL row has `schema_version`, stable `event_id`, ISO 8601 millisecond `timestamp`, `collected_at`, `sensor_id`, `event_type`, and `synthetic=true`. The project-owned types are `network_connection`, `dns`, `http`, `process`, and `service_query`. Connection rows include source/destination IPs, destination port, transport, probe type, observed outcome, packets, bytes, and duration. DNS rows have resolver-visible questions and answers. HTTP rows are emitted by a modeled application sensor, so they can include HTTPS paths only if such an application observation is modeled; the current profile uses HTTP port 80. Process rows exist only for monitored internal sources. Service-query rows follow successful SMB connections. These records are **not native Zeek, Sysmon, firewall, or EDR schemas**.

The JSON truth file carries operation IDs, family, authorization, source, intended tool when relevant, ATT&CK mappings, evidence references, event IDs, generator-only causal links, network translation, and omitted-observation counts. Keep it outside the analyst search index. Raw events do not contain scenario IDs, actor attribution, maliciousness labels, tool identity inferred from network behavior, or expected detection outcomes. `PUBLIC_IPS` are documentation-range public exposures mapped to private inventory hosts; an external scanner never connects directly to the private address in perimeter observations.

The versioned [evidence catalog](../catalogs/recon/evidence-v1.json) cites the [BianLian joint advisory](https://www.ic3.gov/CSA/2023/230516.pdf), [Androxgh0st joint advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a), [Nmap phases](https://nmap.org/book/nmap-phases.html), [Nmap host discovery](https://nmap.org/book/man-host-discovery.html), and [CIC-IDS2017 overview](https://www.unb.ca/cic/datasets/ids-2017.html). It identifies which observations those sources support and lists implementation assumptions. No capture was selected or verified; all scenario profiles are **documented behavior only**, not capture-calibrated. Tool and source sensor versions are unknown. The generator does not assert that the cited reports establish the modeled timing, packet counts, status codes, command lines, or one universal sequence.

## Investigation and Splunk smoke test

Ingest `recon-events.jsonl` only into a test index, using a dedicated sourcetype such as `sec_data_recon_jsonl`. Configure JSON field extraction and map the ISO 8601 `timestamp` to Splunk `_time`; verify a sample's `_time` and `event_id` after ingestion. This repository has **not** run a live Splunk ingest test. The following searches are starting points, not validated CIM mappings:

```spl
index=<test-index> sourcetype=sec_data_recon_jsonl event_type=network_connection
| stats dc(dst_port) as distinct_ports count by src_ip dst_ip
| where distinct_ports >= 3
```

```spl
index=<test-index> sourcetype=sec_data_recon_jsonl event_type=network_connection
| stats dc(dst_ip) as distinct_targets count by src_ip dst_port
| where distinct_targets >= 3
```

```spl
index=<test-index> sourcetype=sec_data_recon_jsonl
| eval actor_ip=coalesce(src_ip,host_ip)
| stats values(event_type) as observed_types values(executable) as executables count by actor_ip
```

Check the truth file only after forming an analyst hypothesis. The approved scanner should exercise contextual suppression despite scan-like network behavior. A behavior-only Nmap variant should not receive authoritative tool attribution from connection rows. A blocked connection has no child application observation, and SYN-only probes have no HTTP response.

## Limits and next validation

The current normalized model does not emulate Zeek connection expiration, realistic packet distributions, UDP ambiguity, passive HTTPS decryption, endpoint coverage variation by individual host, or large-scale temporal merging. The internal and Nmap profiles use project-chosen small target sets. A future calibration workflow must select and verify a CIC-IDS2017 or project-owned capture window, record its checksum, topology, tool/sensor versions, extraction settings, and comparison ranges before any profile can claim capture calibration. Splunk ingestion, extraction, investigation searches, and throughput should be validated in an actual test instance.
