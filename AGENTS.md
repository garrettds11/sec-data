# Agent instructions

Use the [README](README.md) for setup and commands, the [dataset guide](docs/dataset.md) for output and validation, and the [scenario guide](docs/scenarios.md) for authored investigations.

## Before generating

- Ask what the dataset is for, including the attack type, hosts and users involved, time window, and event volume. Confirm these choices before running `create_dataset.py`.
- A run without `--scenario-file` uses the fixed reference story. Do not treat a different seed as a new plot.
- For a custom story, read [the scenario contract](docs/scenarios.md) and [the example scenario](scenarios/file-collection.json). Propose the ordered steps to the user and wait for approval before generating.

## Repository and output

- Do not modify tracked files unless the user asks.
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
- [README.md](README.md) uses CRLF line endings; preserve them when editing it.
