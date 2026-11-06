# Changelog

## v0.1.0 — 2026-11-06

First tagged release of the deterministic synthetic security dataset generator.

### Included

- `create_dataset.py` publishes a single CIM-shaped analyst event package with separate context, truth, and a manifest containing counts and file hashes.
- A seeded, linked investigation covers reconnaissance, authentication, endpoint execution, data access, egress, containment, and follow-up findings. Benign DNS, authentication, network, and web sessions can raise the published event count to a requested target.
- `splunk/TA-sec-data-cim` supplies the project sourcetype, event-time parsing, JSON extraction, event types, tags, and DNS array mappings.
- Standalone vulnerability and compliance exporters retain their JSON and JSONL formats for local analysis and the optional AWS uploader.
- Checked-in fixtures, documentation, and local tests provide a reproducible baseline for later generator changes.

### Validation scope

- The 291-event planted CIM fixture was tested in Splunk Enterprise 10.4.0 with CIM 8.7.0 and `TA-sec-data-cim` 0.1.2. Its event boundaries, timestamps, selected fields, tags, and twelve intended data-model memberships matched the recorded expectations.
- A 100,000-event package was generated and measured at 42,520,967 event bytes. A full million-event file write and Splunk ingest of the background stream were not measured.
- Vendor-shaped Zeek and Windows source fixtures were not verified as drop-in inputs for vendor add-ons.

### Known limits

- The scenario sequence is defined in code. Changing the seed changes repeatable details, not the plot; no natural-language or structured scenario input exists in this release.
- Background events are evenly distributed over the requested window and have no daily activity pattern.
- Synthetic observations do not prove uploaded file contents or a single actor behind every stage of the investigation.

See the [README](README.md) for the primary workflow and the [documentation guide](docs/README.md) for detailed scope and evidence.
