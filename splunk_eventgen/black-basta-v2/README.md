# Black Basta v2 replay

For recurring replay inside Splunk Enterprise, follow the [SA-Eventgen setup guide](../README.md).

This configuration replays the repository's [Black Basta v2 scenario](../../scenarios/cisa/aa24-131a-black-basta-v2.json). The [scenario notes](../../docs/examples/aa24-131a-black-basta-v2-notes.md) explain the fictional investigation and the independent historical indicator observations. Copy the [top-level template](../eventgen.conf) when adding another scenario.

## Prepare the sample

Generate Black Basta v2 using the [repository quick start](../../README.md#3-select-a-scenario-and-generate-data). The reference fixture uses seed 2, 23 hosts, start time 2024-11-12 08:00 UTC, a 120-minute window, and 10,000 events.

From the repository root, in the same PowerShell session that generated the run:

~~~powershell
& $python .\splunk_eventgen\prepare_sample.py $outputDir `
  .\output\splunk-eventgen\black-basta-v2\black-basta-v2.csv `
  --scenario-id cisa-aa24-131a-black-basta-composite-v2
if ($LASTEXITCODE -ne 0) { throw 'Eventgen sample preparation failed.' }
~~~

The helper reads the manifest and the run's `events/` streams. It merges them by UTC time and event ID, keeping each JSON event intact. Each CSV row carries the original filename as Splunk `source` and the reporting device (`dvc`) as `host`. Keep one CSV for the whole scenario so the firewalls, DNS, endpoint, and authentication logs share the same replay clock. The default sample path is under `output/`. For another run, choose a new sample directory and update `sampleDir` in a copy of the config.

## Run Eventgen

Run standalone [Splunk Eventgen](https://github.com/splunk/eventgen) in a separate, compatible Python environment on a UTC host. From the repository root, with Eventgen's interpreter active:

~~~bash
TZ=UTC python -m splunk_eventgen generate splunk_eventgen/black-basta-v2/eventgen.conf
~~~

The config plays the sample once at normal speed and writes JSONL to stdout. Set `timeMultiple = 0.01` in a copy for a faster preview, keeping `sampleDir` relative to that copy or setting it to the absolute sample directory. Eventgen moves event times to the replay window and the config preserves the millisecond UTC format expected by [TA-sec-data-cim](../../splunk/TA-sec-data-cim). Eventgen 7.2.1 applies each source gap one event late and timestamps using its wall clock. Event order is preserved, with up to 0.741 seconds of gap displacement in the reference sample at normal speed, plus runtime overhead. Use the generated JSONL for checks that require exact historical timestamps or time deltas.

For local Splunk ingest with per-event metadata, install TA-sec-data-cim, create the `sec_data` index, and point a private config copy at the same-host HEC listener. Set `outputMode = httpevent` and use the following setting with your listener port and token. Eventgen 7.2.1's HEC output disables TLS certificate verification, so this example uses loopback.

~~~ini
httpeventServers = {"servers":[{"protocol":"https","address":"127.0.0.1","port":"8088","key":"REPLACE_WITH_HEC_TOKEN"}]}
~~~

Run with `generate <config-path> --keepoutput` to use HEC. Search the replay window. Use a clean lab index or filter to a single run when comparing to the source manifest.

~~~spl
index=sec_data sourcetype=secdata:cim:json
| stats count by source sec_data_cim_dataset
| sort source sec_data_cim_dataset
~~~

## Expected analyst telemetry

| Scenario evidence | Replay sources | CIM dataset |
| --- | --- | --- |
| Assessment finding for PrintNightmare | `vulnerability.jsonl` | `Vulnerabilities.Vulnerabilities` |
| AnyDesk, discovery, credential-access and defense-impairment attempts, PsExec, Rclone, and encryptor launch | `sysmon.jsonl` | `Endpoint.Processes` |
| Historical hashes and paths, encryptor delivery, renamed files, and ransom note | `sysmon.jsonl`, `endpoint-lab.jsonl` | `Endpoint.Filesystem` |
| Domain lookups with NXDOMAIN responses | `resolver-dns.jsonl` | `Network_Resolution.DNS` |
| Remote-support connection, discovery and lateral traffic, historical IP observations, exfiltration, and blocked retry | `eastwest-firewall.jsonl`, `egress-firewall.jsonl`, `zeek-conn.jsonl`, `response-firewall.jsonl` | `Network_Traffic.All_Traffic` |
| Privileged account use, PsExec and RDP logons, and sensitive file reads | `windows-security.jsonl`, `windows-file.jsonl` | `Authentication.Authentication`, `Data_Access.Data_Access` |

Routine traffic adds web, proxy, ingress and authentication sources to the exercise. The reference run has 10,000 rows across 17 sources, including 280 prescribed observations covering 27 steps. Both the authorized Rclone backup and the suspicious transfer are included. The email flood and Teams conversation are narrative context. The event payloads use the repository's CIM-shaped JSON schemas.
