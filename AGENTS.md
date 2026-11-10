# Agent instructions

Use the [README](README.md) for setup and commands, the [dataset guide](docs/dataset.md) for output and validation, and the [scenario guide](docs/scenarios.md) for authored investigations.

## Author a scenario from any story source

- Read [general authoring](docs/scenario-authoring.md), the [contract](docs/scenarios.md), and [example](scenarios/file-collection.json) before authoring. Inspect supported fields/context using validate_scenario.py --describe-contract and --describe-context with the intended seed/host count.
- Recognize three story sources: **CISA-oriented**, **AI-generated**, and **human-generated**. Source is independent of assistance: humans may manually customize any input, and AI may translate a human narrative. The generic request to create a threat story and generate synthetic data defaults to an AI-generated plausible fictional story unless the user supplies another source.
- For a human-generated story, preserve the user's intent and clarify missing causal links. For AI-generated stories, propose a plausible sequence and label assumptions. Do not treat a seed change as a new plot.
- For CISA, follow [the human/machine advisory procedure](docs/cisa-scenario-authoring.md). Obtain the full publication and chosen revision, not just an ID/catalog summary. Record source locations and inventory IOCs, tactics/techniques, software and weaknesses. Preserve qualifications and distinguish documented facts, hypotheses and fictional additions. Explain unsupported details and unselected alternatives. Do not invent indicator relationships, hashes or outcomes; old indicators do not establish current maliciousness.
- Deliver one contract-compatible scenario JSON per independent story and companion notes for source facts, assumptions, omissions, ordered steps and run commands. Keep narrative/answer labels outside analyst observations. Scenario JSON does not install software, enforce privileges or simulate actual malware effects.
- Follow [AI handoff instructions](docs/ai-authoring.md) for chats lacking repository access: identify the context/files needed and do not claim validation or generation was performed if no execution occurred.
- Run validate_scenario.py --scenario-file PATH with the intended seed, host count, duration and optional target-events. Report validation limits. Use the same settings in the eventual generation command. Structural validation is separate from semantic/source review.

## Before generating

- Ask what the dataset is for, including the attack type, hosts and users involved, time window, and event volume. Confirm these choices before running `create_dataset.py`.
- A run without `--scenario-file` uses the fixed reference story. Do not treat a different seed as a new plot.
- For a custom story, read [the scenario contract](docs/scenarios.md) and [the example scenario](scenarios/file-collection.json). Propose the ordered steps to the user and wait for approval before generating.

## Repository and output

- Do not modify tracked files unless the user asks.
- Keep reviewed reusable inputs under scenarios/ and source notes under docs/examples/ when the user authorizes repository changes. Keep working drafts and generated datasets under output/.
- Write generated files only under the Git-ignored `output/` directory. Choose a new output directory name that does not already exist.
- After a run, report the output path, the exact command used, and the seed.

## Splunk ingest

- Create the target index before ingest. `splunk add oneshot` can report a file as added even when Splunk later drops its events because the index is missing.
- Index only `events/*.jsonl` with sourcetype `secdata:cim:json`. Never index `context/` or `truth/`; `truth/` contains the answer key.
- After ingest, compare the indexed event count with `event_records` in `dataset-manifest.json`. Use a fresh index or isolate the run if the index contains other data.
- Do not re-ingest a run into an index that already holds it; doing so duplicates events.
- Search **All Time** when verifying a run, because event timestamps follow its chosen `--start-time` rather than the ingest time.

## Housekeeping

- The [README](README.md) targets Python 3.12.
- Preserve the repository's .gitattributes text normalization when editing Markdown; avoid unrelated line-ending churn.
