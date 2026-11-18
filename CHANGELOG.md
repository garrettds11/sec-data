# Changelog

## Unreleased

- Add SafePay AA26-293A v1 with the user-supplied original STIX snapshot, source reconciliation, 14 steps/85 observations and 62 typed coverage assertions. Support SHA-1/hostname coverage and case-sensitive SSDEEP filesystem metadata; document independent historical fixtures and fictional exercise settings.

- Scenario files may declare a short `output_name`. Dataset CLI runs without `--output-dir` now allocate readable `<name>-runNNN` folders under `output/` (or `--output-root`), with atomic reservations for concurrent runs. Explicit new output paths retain their existing behavior. `--json` reports the allocated path for automation.
- Black Basta v2 uses `black-basta-v2`; file collection uses `file-collection`. Update the README and walkthrough to capture the chosen path automatically for validation and Splunk ingestion.

- Add Black Basta v2 with original May publication Tables 7–11 plus the explicitly retained November IOC set; keep v1 unchanged. Add typed filesystem/process hash fields, Linux filesystem observations, a source inventory, and event-ID-backed publication coverage checks that fail on missing IOCs.

- Use Python 3.15 as the default for new environments, declare it in `.python-version`, document venv migration, and test Python 3.12/3.15 on Windows/Linux.

- Added manual and AI-assisted authoring paths for CISA-oriented, AI-generated and human-generated stories, with shared source fidelity and review instructions.
- Added validation-only and contract/context inspection commands, a minimal manual template and the source-documented Black Basta example.
- Shared scenario validation with compilation, including entity collision checks, finite numeric values and boolean authorization metadata.

- Make the README's PowerShell run settings explicit variables, use descriptive output directory names, and link other guides to the canonical example and measured dataset snapshot.
- Route routine events into sensor-specific source files and merge planted observations into those files by event time. The default routine mix now includes web, file, egress, and ingress sessions.
- Add a versioned JSON scenario contract so a person or LLM can author an ordered investigation, refer to shared assets and identities, add external entities, and generate a tailored CIM-shaped package without changing generator code.
- Record source counts and planted versus routine counts in the package manifest. Keep scenario descriptions and causal links in `truth/`.
- The new event layout is not yet validated in a live Splunk ingest. The v0.1.0 lab results below remain evidence for the earlier planted fixture.

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
