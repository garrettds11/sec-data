# Synthetic DNS and Zeek JSON export

The recon generator can export modeled DNS observations as both project-owned normalized JSONL and a separate Zeek-shaped JSON `dns.log`. The Zeek file contains only the fields a passive DNS sensor could derive from the modeled UDP exchange; scenario labels and synthetic metadata remain in the separate truth file. This renderer follows the documented [Zeek `DNS::Info` fields](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html) and [JSON examples](https://docs.zeek.org/en/current/reference/logs/dns.html). It has **not** been produced by Zeek from packets or validated with a Splunk add-on installation.

```powershell
python .\create_recon_events.py --seed 42 `
  --start-time 2026-10-22T12:00:00Z --duration-minutes 60 `
  --output .\output\recon-events.jsonl `
  --truth-output .\output\recon-truth.json `
  --zeek-dns-output .\output\dns.log
```

The normal output remains the comprehensive event stream. `dns.log` is JSONL with Zeek names such as `ts`, `uid`, `id.orig_h`, `id.resp_h`, `trans_id`, `query`, `qtype_name`, `rcode_name`, `answers`, and `TTLs`. A query without an observed response omits response-only fields. The `uid` is a stable synthetic connection identifier derived from the normalized event ID; each modeled UDP query uses a separate client port. It is not correlated with a Zeek `conn.log`, because this generator does not emit one. The rendered rows contain no non-Zeek `synthetic` flag; handle the whole file as synthetic test data.

Each browsing session first resolves the web host's A record. A five-case diagnostic rotation adds a no-answer AAAA lookup, NXDOMAIN, SERVFAIL, CNAME answer, or unanswered query followed by a successful retry. Address answers have TTLs and same-operation repeats within a TTL use the modeled client cache, so those repeated page requests need not cause another DNS query. These cases and timings are project assumptions, not measurements from a Zeek capture. The cache currently resets per operation, which limits realism across operation boundaries.

## Splunk mapping and validation

The [TA for Zeek 1.0.11 listing](https://splunkbase.splunk.com/app/5466/) says it parses JSON and TSV Zeek logs into CIM 6.x and prompts for login to download. A [Splunk Security Content manifest](https://github.com/splunk/security_content/blob/develop/contentctl.yml) points to a [1.0.11 archive in Splunk's Attack Range binary store](https://attack-range-appbinaries.s3.us-west-2.amazonaws.com/ta-for-zeek_1011.tgz). The downloaded 72,288-byte archive had SHA-256 `d5fabacc1cae4c66b19b633d165687f11e10772c1d734746e674e2ee9f7fdcfc`; its `app.conf` reports version 1.0.11. It was inspected locally and is **not redistributed** in this repository. A live Splunk instance was unavailable, so **CIM compliance remains unverified**. The intended target is the [Network Resolution (DNS) data model](https://help.splunk.com/en/data-management/common-information-model/6.3/data-models/network-resolution-dns), whose DNS event dataset uses the `network`, `resolution`, and `dns` tags.

Static inspection of the package's `default/` configuration found:

- `eventtypes.conf` defines `zeek_dns` for `sourcetype=zeek:dns` and legacy `bro_dns` sources. `tags.conf` enables `network`, `dns`, and `resolution` for both event types.
- `props.conf` under `[zeek:dns]` aliases `qtype_name` to `record_type`, `rcode_name` to `reply_code`, `trans_id` to `transaction_id`, `rtt` to `duration` and `response_time`, and answers to `answer`; it calculates `message_type` as `Response` or `Query`. Its source/destination aliases use underscore names such as `id_orig_h`, while Zeek JSON uses dotted keys such as `id.orig_h`. The actual JSON extraction/alias behavior needs an ingest test.
- The legacy `[bro:dns:json]` stanza has a different, narrower mapping. It sets `message_type` to uppercase `RESPONSE`/`QUERY` and selects only the first answer for `answer`; those values do not directly match the CIM reference's prescribed case and multivalue expectation. Do not assume the two sourcetypes behave identically.
- `metadata/default.meta` has `export = none` by default. The add-on installation guide instructs administrators to review permissions before exporting knowledge objects system-wide. Check that the data model search context can see the event types and tags.

| Zeek field | Candidate CIM field | Check in the pinned add-on |
| --- | --- | --- |
| `ts` | `_time` | Timestamp parsing and timezone |
| `id.orig_h`, `id.orig_p` | `src`, `src_port` | Source extraction/aliases |
| `id.resp_h`, `id.resp_p` | `dest`, `dest_port` | Resolver destination extraction/aliases |
| `query`, `qtype_name` | `query`, `record_type` / `query_type` | Query type and value normalization |
| `rcode`, `rcode_name` | `reply_code_id`, `reply_code` | Prescribed CIM values and query-only rows |
| `answers`, `TTLs` | `answer`, `ttl` | Multivalue handling and one-to-one pairing |
| `trans_id`, `proto`, `rtt` | `transaction_id`, `transport`, `response_time` | Numeric types and seconds |

To validate, install the pinned TA package and CIM version in a test Splunk instance. Test both the TA's `zeek:dns` and legacy JSON ingestion paths to establish which one correctly extracts this JSON. Compare source rows with extracted fields and verify `_time`, tag membership, numeric and multivalue types, source/destination aliases, response code values, and query-only rows. Check the DNS dataset's required fields using `pytest-splunk-addon` or an equivalent Splunk data model validation. Save the TA package hash, chosen sourcetype, sample search results, and any gaps before calling the output CIM compliant. Do not invent unavailable fields such as an observed response to a timeout.
