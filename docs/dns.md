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

The [TA for Zeek 1.0.11 listing](https://splunkbase.splunk.com/app/5466/) says it parses JSON and TSV Zeek logs into CIM 6.x, but downloading its package requires a Splunk login. The add-on configuration and a live Splunk instance were unavailable for this change. **CIM compliance is therefore unverified.** The intended target is the [Network Resolution (DNS) data model](https://help.splunk.com/en/data-management/common-information-model/6.3/data-models/network-resolution-dns), whose DNS event dataset uses the `network`, `resolution`, and `dns` tags.

| Zeek field | Candidate CIM field | Check in the pinned add-on |
| --- | --- | --- |
| `ts` | `_time` | Timestamp parsing and timezone |
| `id.orig_h`, `id.orig_p` | `src`, `src_port` | Source extraction/aliases |
| `id.resp_h`, `id.resp_p` | `dest`, `dest_port` | Resolver destination extraction/aliases |
| `query`, `qtype_name` | `query`, `record_type` / `query_type` | Query type and value normalization |
| `rcode`, `rcode_name` | `reply_code_id`, `reply_code` | Prescribed CIM values and query-only rows |
| `answers`, `TTLs` | `answer`, `ttl` | Multivalue handling and one-to-one pairing |
| `trans_id`, `proto`, `rtt` | `transaction_id`, `transport`, `response_time` | Numeric types and seconds |

To validate, install a pinned TA for Zeek package and CIM version in a test Splunk instance, then use the TA's documented JSON DNS sourcetype. Inspect the installed `props.conf`, `transforms.conf`, `eventtypes.conf`, `tags.conf`, and relevant lookups. Ingest a small generated `dns.log` into a test index and compare source rows with extracted fields. Verify `_time`, tag membership, numeric and multivalue types, and response code values, including unanswered queries. Check the DNS dataset's required fields using `pytest-splunk-addon` or an equivalent Splunk data model validation. Save the TA package version/hash, sourcetype, sample search results, and any gaps before calling the output CIM compliant. Do not invent unavailable fields such as an observed response to a timeout.
