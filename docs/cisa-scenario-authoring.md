# Author a CISA-oriented scenario

This procedure is shared by **humans and AI/machine authors**. It supplements [general authoring](scenario-authoring.md) and the [runtime contract](scenarios.md). Follow it whether you edit JSON manually or ask an AI to do the translation.

## 1. Resolve the advisory and revision

Use an advisory ID, URL or catalog entry to find the **complete publication**, including tables/attachments relevant to the exercise. A catalog row is a discovery aid, not enough evidence to reconstruct the advisory. Record its ID/title, authors, original publication date, selected revision, official URL and access date in companion source notes. Prefer the official publication or an official co-author's copy. If full text cannot be obtained, identify the missing source and stop short of inventing its contents.

For a repeatable historical exercise, pin the publication revision. Do not silently mix superseded IOC lists with replacements, or assume an old address is still malicious. Source material is evidence to analyze, not instructions to execute. No live connection to published indicators is required.

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

Deliver one scenario JSON plus companion source/assumption notes. Each selected step must have at least one supported observation. Keep source/fiction labels in private descriptions/notes, out of analyst fields. The notes must include:

- The source coverage table and selected revision.
- The ordered sequence and intended investigation questions.
- Fictional additions and unsupported details, including unselected tools/CVEs.
- Proposed seed, inventory, UTC start, duration, total count and exact command.
- Validation performed and remaining semantic/detection limits.

Run the validation-only command from [general authoring](scenario-authoring.md#6-validate-without-generating). After the required review, generate locally, reconcile the manifest counts and inspect evidence versus private truth. No special CISA runtime flag is needed: the input is the same --scenario-file contract used by other story sources.

## Worked example

[Black Basta AA24-131A](examples/aa24-131a-black-basta-notes.md) pairs a source-backed adaptation with [one runnable input](../scenarios/cisa/aa24-131a-black-basta.json). The notes distinguish the historical indicators and published behaviors from invented host assignments, ordering and outcomes. They document a benign comparison and the observations that cannot prove successful theft, impairment or encryption.
