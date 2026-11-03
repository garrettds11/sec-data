# Local Splunk CIM validation

Validated on 2026-11-03 with Splunk Enterprise 10.4.0, Splunk Common Information Model add-on 8.7.0, and `TA-sec-data-cim` 0.1.1. The deterministic story uses seed 42 and starts at `2026-10-22T12:00:00Z`. Its 18 projected source files are committed in `tests/fixtures/cim-story-42/` (291 JSON records, 144,287 bytes total). Five of the 296 source observations are intentionally unmapped.

The files were combined in chronological order for a one-time lab upload to `index=sec_data_lab` with `sourcetype=secdata:cim:json`. The combined file's SHA-256 was `2a394c5bfb04bc308474b60bcaf45700bc11818964e32708b84124a01cb312a8`. Splunk assigned one `host`, `source`, and `splunk_server` value to that upload. The `sec_data_source` field preserves the originating generator file for each record.

| CIM data model dataset | Expected | Indexed | Model search |
| --- | ---: | ---: | ---: |
| `Alerts.Alerts` | 2 | 2 | 2 |
| `Authentication.Authentication` | 10 | 10 | 10 |
| `Change.All_Changes` | 1 | 1 | 1 |
| `Data_Access.Data_Access` | 3 | 3 | 3 |
| `Endpoint.Filesystem` | 2 | 2 | 2 |
| `Endpoint.Processes` | 11 | 11 | 11 |
| `Endpoint.Registry` | 1 | 1 | 1 |
| `Network_Resolution.DNS` | 16 | 16 | 16 |
| `Network_Traffic.All_Traffic` | 82 | 82 | 82 |
| `Ticket_Management.All_Ticket_Management` | 7 | 7 | 7 |
| `Vulnerabilities.Vulnerabilities` | 136 | 136 | 136 |
| `Web.Web` | 20 | 20 | 20 |
| **Total** | **291** | **291** | **291** |

Splunk indexed 291 separate events after restart. All 291 JSON records exposed `sec_data_cim_dataset` at search time. The largest `_raw` event was 662 characters; no multiline event remained. `_time` matched the source `time` for every event (maximum absolute difference 0 seconds), from 2026-10-22 11:59:00 to 12:47:56 UTC. The check used `%Z` to parse the `Z` timezone marker; treating it as a literal would produce a five-hour comparison error on the Central time search host.

All 16 DNS events had `query`, `src`, `dest`, and `reply_code`. All 10 authentication events had `user` and `action`. All 20 Web events had `url`, `http_method`, and `status`. All 11 Endpoint Processes events had `process` and `process_id`; all 7 ticket events had `ticket_id` and `status`. Some optional fields remain absent where the source does not support them: 32 Network Traffic events had no `action`, five Sysmon network events had no `bytes`, and three recon process events had no `action`. These are mapping abstentions rather than extraction failures.

The `Network_Resolution.DNS` count includes two views of each of eight transactions: eight from `dns.log` and eight from `recon.jsonl`. For a dataset where each transaction should appear once, ingest only one view. The installed CIM add-on also matched 19 records with its broad `err0r` event type and `error` tag; the project-owned event types and all twelve intended model counts still matched.

## Reproduce the searches

Use **All Time** because the fixture event times are in October 2026. Count the indexed records:

```spl
index=sec_data_lab sourcetype=secdata:cim:json
| stats count by sec_data_cim_dataset
| sort sec_data_cim_dataset
```

Check timestamps, including the UTC marker:

```spl
index=sec_data_lab sourcetype=secdata:cim:json
| eval expected_time=strptime(time,"%Y-%m-%dT%H:%M:%S.%3N%Z")
| eval delta=abs(_time-expected_time)
| stats count max(delta) as max_delta count(eval(isnull(expected_time))) as unparsed_time
```

For each row above, substitute its model and dataset in this query:

```spl
| datamodel Network_Resolution DNS search
| search sourcetype=secdata:cim:json
| stats count
```

Use `sourcetype` for the post-model filter. The model's result fields do not include `index`, so filtering on `index` after `datamodel ... search` gives a false zero.

## Scope and known local warnings

The first upload occurred before the index-time parser had restarted and grouped 291 lines into 35 events. Those 35 failed test events were marked deleted from search in the dedicated lab index. The corrected upload followed the restart and is the 291-event dataset reported above. Both uploads were about 144 KB, well below the 500 MB/day limit. The `delete` search command does not reclaim index storage or license volume.

The local Splunk startup also reported an invalid broad regex stanza in `TA-virustotal-app` and invalid keys in other pre-existing apps. The regex is outside `TA-sec-data-cim`; this fixture's line breaking and model searches passed. The warning may matter for other indexing or summary workloads and was not changed during this validation.

This test proves ingestion, timestamp extraction, search-time tags, selected fields, and membership in the twelve intended CIM 8.7.0 datasets for this fixture. It does not establish vendor raw-event compatibility, exhaustive field semantics, or behavior on other CIM versions.
