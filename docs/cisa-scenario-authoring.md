# Author a CISA-oriented scenario

This procedure is shared by **humans and AI/machine authors**. It supplements [general authoring](scenario-authoring.md) and the [runtime contract](scenarios.md). Follow it whether you edit JSON manually or ask an AI to do the translation.

## 1. Resolve the advisory and revision

Use an advisory ID, URL or catalog entry to find the **complete publication**, including tables/attachments relevant to the exercise. A catalog row is a discovery aid, not enough evidence to reconstruct the advisory. Record its ID/title, authors, original publication date, selected revision, official URL and access date in companion source notes. Prefer the official publication or an official co-author's copy. If full text cannot be obtained, identify the missing source and stop short of inventing its contents.

For a repeatable historical exercise, pin the publication revision. Do not silently mix superseded IOC lists with replacements, or assume an old address is still malicious. Source material is evidence to analyze, not instructions to execute. No live connection to published indicators is required.

## Required STIX JSON source review

For each advisory, explicitly inspect its attachment links for **STIX JSON**. When the advisory publishes a STIX JSON attachment, retrieving and inspecting that file is required before finalizing its scenario and indicator coverage. The publication supplies behavior and qualifications; STIX supplies structured CTI and may contain values absent from the publication tables. Neither is assumed to be a complete substitute for the other.

1. Resolve the exact JSON URL from the advisory or its official PDF. Retrieve the original bytes and parse them as JSON; reject error pages and malformed content. Do not derive a filename and assume it exists.
2. Record the official URL, retrieval date, file SHA-256, STIX version, bundle/document ID when present, and relevant object IDs and versions in source notes or the coverage catalog. Retain a reproducible source snapshot or a documented immutable reference outside analyst events.
3. Inventory indicator patterns and relevant observable objects, including IPs, domains, URLs, hostnames, filenames/paths and all supplied hash algorithms. Review compound patterns, relationships, validity periods, revoked/deprecated status and confidence/markings. Do not flatten an AND pattern into independent evidence and claim the whole indicator matched.
4. Separate total objects, indicator objects, pattern assertions and distinct typed values. Deduplicate values without losing their provenance. Preserve original values and document normalization, such as refanging or case folding. Do not count identities, markings or ATT&CK objects as additional IOCs.
5. Reconcile this inventory against the chosen publication revision. Record values present only in STIX, only in the publication, or with differing qualifications. Explicitly retain, represent, or explain omissions; never assume PDF-table coverage proves STIX coverage.
6. Map every in-scope value or pattern to supported event fields and verification assertions. If a required type is unsupported, implement the needed support or disclose the limitation before completion. Merely mentioning an IOC in truth, context or narrative does not plant it in analyst evidence.

If the JSON cannot be obtained, record the exact failing URL and access error, request the original attachment from the user, and continue only independent work. **Do not finalize a substitute PDF-only scenario or claim STIX parity.** A third-party copy may help investigation, but cannot establish identity with the official attachment without verification. Use a different source/scope only if the user explicitly authorizes it. If an advisory publishes no STIX JSON, document that finding rather than inventing an attachment; this exception does not apply to an existing attachment blocked by HTTP 403.

STIX `created`, `modified`, `valid_from`, `valid_until`, and observed-time values have distinct CTI meanings. They are not automatically an incident's start, attack duration, or affected-host count. Keep generator settings separately documented as synthetic assumptions unless source evidence establishes them. STIX is an authoring source, not a generator-compatible `--scenario-file` input.

## 2. Extract source facts before inventing a story

Build a human-readable source coverage table in the notes:

| Detail | Source location | Qualification | Planned representation |
| --- | --- | --- | --- |
| IOC: address/domain/hash/artifact | Page, table or attachment | Historical, suspected, likely, or confirmed as stated | Supported event field, contextual note, or explicit omission |
| Tactic/technique | Section and source ATT&CK ID if given | Observed behavior versus potential impact | Supported observation and evidence boundary |
| Tool/software | Section/table | Legitimate tool abuse, malware, or alternative path | Selected tool/process; do not force every alternative into one chain |
| Weakness/CVE | Section and affected software | Exploited in reporting versus hypothetical risk | Contextual assessment, supported exploit evidence, or omission |

Preserve exact indicator values when using them for offline matching and retain the source's qualifications. Do not invent hashes, DNS domain-to-IP associations, tool versions or technique IDs and label them as published facts. If the compiler cannot carry a detail in a supported field, retain it in notes rather than overloading another field.

## 3. Propose one coherent adaptation

Identify documented facts, source-based hypotheses and fictional additions separately. The organization, existing repo asset/account mappings, timing, filenames, byte counts, prerequisite privileges, ordering across reported incidents and response actions commonly require invention. Label them.

A report about several affiliates or incidents is not a single victim timeline. Select a coherent branch and document alternatives not selected. For AI workflows, present ordered steps, gaps and run settings for approval before generating data. For manual workflows, review them against the same checklist.

Do not equate a vulnerability finding with exploitation, a launched utility with successful credential theft, a remote flow with a particular C2 protocol, or a filename suffix with proven encryption. Describe the limits an analyst should retain.

## 4. Map facts to the current generator

Inspect supported fields and context with validate_scenario.py --describe-contract / --describe-context. Reuse declared internal assets/identities and plausible listening services. JSON can add external entities; it does not provision internal services, install software, enforce permissions or simulate security-state changes.

Email, chat/call content, unsupported product telemetry, malware bytes and cryptographic outcomes may require narrative-only treatment or a future code extension. State that explicitly. Do not encode unsupported telemetry as fake generic HTTP or process events solely to pass validation.

## 5. Produce, validate and review

Complete the required STIX JSON review above, then deliver one scenario JSON plus companion source/assumption notes. Each selected step must have at least one supported observation. Keep source/fiction labels in private descriptions/notes, out of analyst fields. The notes must include:

- The source coverage table and selected revision.
- The ordered sequence and intended investigation questions.
- Fictional additions and unsupported details, including unselected tools/CVEs.
- Proposed seed, inventory, UTC start, duration, total count and exact command.
- Validation performed and remaining semantic/detection limits.

Run the validation-only command from [general authoring](scenario-authoring.md#6-validate-without-generating). After the required review, generate locally, reconcile the manifest counts and inspect evidence versus private truth. No special CISA runtime flag is needed: the input is the same --scenario-file contract used by other story sources.

## Verify indicator coverage separately

Inventory the exact publication and STIX JSON attachment revisions before finalizing any CISA scenario. If the objective includes matching a published indicator set, define its scope against that complete source inventory. Do not claim that a newer revision's replacement list covers an older STIX attachment. State whether each input's bytes were actually available. Keep every source indicator with its type, original value, normalization, qualification, intended field and represented/omitted reason in a companion machine-readable catalog.

Use `validate_ioc_coverage.py --dataset-dir PATH --coverage-file CATALOG` to verify supported publication assertions against actual `events/*.jsonl` after generation. An optional `--output NEW_REPORT.json` records the event IDs supporting each match; missing values cause a nonzero exit. The checker does not count context, truth, narrative mentions or unrelated fields as evidence. Structural validation and event counts alone cannot establish source-indicator completeness. Review catalog completeness against the source separately.

## Worked example

[Black Basta AA24-131A](examples/aa24-131a-black-basta-notes.md) pairs a source-backed adaptation with [one runnable input](../scenarios/cisa/aa24-131a-black-basta.json). The notes distinguish the historical indicators and published behaviors from invented host assignments, ordering and outcomes. They document a benign comparison and the observations that cannot prove successful theft, impairment or encryption.

For historical original-publication IOC matching, use [Black Basta v2](examples/aa24-131a-black-basta-v2-notes.md). V1 above remains the narrower November-revision story. V2 explicitly combines both historical source sets and adds typed hashes plus machine-checked export coverage; it does not claim attachment/CSV parity without those bytes.
