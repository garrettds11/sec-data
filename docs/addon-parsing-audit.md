# Static add-on parsing audit for generated fixtures

This audit compares the checked-in `tests/fixtures/story-seed42/` records with
the pinned add-on configuration already inspected for issue #22. It is a
configuration review, **not** a Splunk ingest or CIM inclusion result. The
archives are kept in ignored `output/reference/` and are not redistributed.

| Add-on | Inspected version | SHA-256 |
| --- | --- | --- |
| TA for Zeek | 1.0.11 | `d5fabacc1cae4c66b19b633d165687f11e10772c1d734746e674e2ee9f7fdcfc` |
| Splunk Add-on for Microsoft Windows | 10.0.1 | `444a0894c6a954f4453cf398e1414a29852de23bb7ea9121dd7c4144903a86c6` |
| Splunk Add-on for Sysmon | 5.0.0 | `3b42abf255fbd794cdfa588c3ad152e63f4b62e5665aad0b2c8dd7a23a3b5818` |

## Concrete format mismatches

| Generated data | Add-on rule | Finding |
| --- | --- | --- |
| `dns.log` and other Zeek-shaped JSONL | TA for Zeek's `[zeek]` stanza sets `INDEXED_EXTRACTIONS = tsv` and `KV_MODE = none`. Its `[zeek:dns]` aliases refer to `id_orig_h` and `id_resp_h`. | The fixture contains JSON with keys such as `id.orig_h`. Assigning `zeek:dns` to these JSON records does not follow the add-on's configured TSV path. Whether another Splunk extraction or override supplies the expected fields requires a live test. |
| Zeek-shaped JSONL | The add-on also has a `[bro:json]` source-name transform that selects `bro:<log>:json`; `[bro:dns:json]` has JSON-oriented DNS mappings and DNS tags through `bro_dns`. | This is a possible ingest path for the fixture. It has different semantics: `EVAL-message_type` emits uppercase `RESPONSE`/`QUERY`, and `EVAL-answer` selects the first answer. Test the exact sourcetype, event boundary, multivalue fields, and CIM values before using it. |
| `windows-security.xml`, `windows-file.xml` | TA-Windows `[XmlWinEventLog]` disables automatic key-value extraction and calls `eventdata_xml_data`. That transform's `REGEX` matches `<Data Name='...'>` with single quotes. | The fixture uses `<Data Name="...">` with double quotes. The inspected transform does not match those elements. Other XML extraction paths or installed configuration may affect the final result; the generated `EventData` fields cannot be assumed to extract through this rule. |
| `sysmon.xml` | TA-Sysmon's `sysmon-data` transform matches `<Data Name='...'>`; its source-specific `TIME_PREFIX` expects `<Data Name='UtcTime'>`. | The fixture's `<Data Name="...">` does not match either expression. Sysmon field and `UtcTime` extraction through these rules is at risk even though the XML itself is well formed. |

The single-quote observations are direct regex comparisons against the first
checked-in Windows Security and Sysmon XML records. They do not establish that
the add-ons are defective for genuine source events, which may reach Splunk
through a different collection and rendering path.

## Implication for the project

The generated Zeek JSON and Windows XML are useful **synthetic source
projections**, but the current offline checks do not justify treating them as
drop-in replacements for the named add-ons' supported raw input. The
project-owned normalized recon, edge, web-auth, alert, and case-action JSONL
have no claimed vendor add-on; they need explicit sourcetypes and mapping if
they are to participate in CIM searches.

## Selected direction

The project will emit a **separate CIM-shaped JSONL projection** from its
synthetic world model, while retaining the source-shaped evidence. The current
fixture is not already CIM-ready: for example, `dns.log` uses `id.orig_h` and
`id.resp_h` rather than `src` and `dest`, and the Windows authentication JSONL
uses `TargetUserName` and `IpAddress` rather than the corresponding CIM fields.
The new projection should use CIM names and value semantics where the modeled
source supports them, without inventing unavailable observations or leaking
generator truth.

Give the CIM-shaped files project-owned sourcetypes and explicit event-time
parsing. A small project-owned Splunk add-on can then provide event types,
tags, and any remaining calculated fields or aliases. The vendor technology
add-ons are optional schema references, not runtime dependencies. The Splunk
Common Information Model add-on remains the target for testing data-model
membership in a live Splunk instance. Keep generator truth files out of the
analyst index. The XML projections and vendor-shaped Zeek JSON can remain as
source-format examples; their resemblance to a vendor log does not make them
compatible with that vendor's add-on.

Run a focused live ingest test of the project-owned mapping and record
`_time`, event boundaries, extracted fields, tags, and data-model membership.
Static inspection cannot prove the effective Splunk configuration.

If a future test specifically needs to exercise a vendor add-on, obtain a
genuine sample through its documented collection path, match its event framing
and raw syntax, then compare the generated record against the add-on's
`props.conf`, `transforms.conf`, `eventtypes.conf`, and `tags.conf`. That is
separate vendor-fidelity work, not a prerequisite for the synthetic CIM dataset.

Track the live result and any generator or mapping changes in issue #22.
