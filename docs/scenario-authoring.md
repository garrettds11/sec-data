# Create or customize a story

This guide is for human authors and AI/machine authors. Both produce **one scenario JSON per independently runnable story** and use the same validator and generator. AI is optional for authoring and is not a runtime dependency.

## 1. Choose the story source

| Source | Starting point | Required review |
| --- | --- | --- |
| CISA-oriented | A complete advisory and its revision, optionally selected from a catalog | Follow [CISA authoring](cisa-scenario-authoring.md); preserve documented facts and identify fictional additions. |
| AI-generated | Ask AI to propose a plausible scenario for an investigation objective | Label it fictional; review prerequisites, privileges, sensor visibility and evidence limits. |
| Human-generated | Supply your own narrative, observations or ordered actions | Preserve the author's intent; clarify missing links and convert it to supported observations. |

Story source is independent of authoring assistance. A person can manually encode a CISA story or edit an AI-proposed story; AI can translate a human story into JSON. The included reference story can also be run without authoring anything.

## 2. Define the exercise before generating

Record the investigation objective, story source, hosts/users, desired outcome, UTC start, duration, seed and total event count. For an AI-authored story, review and approve the proposed ordered steps and settings before the AI generates a dataset. A human working manually performs this review themselves. Do not manufacture missing source facts to fill gaps.

The authoring deliverables are a scenario JSON and, when source attribution or assumptions need explanation, companion Markdown notes. Only the JSON is a runtime input. Notes should distinguish evidence from narrative, document limitations and give the exact future command. A CISA story always needs source notes.

## 3. Inspect the available contract and inventory

From the repository root, after the [README setup](../README.md#quick-start-generate-a-dataset):

~~~powershell
$python = '.\.venv\Scripts\python.exe'
& $python .\validate_scenario.py --describe-contract
& $python .\validate_scenario.py --describe-context --seed 42 --host-count 23
~~~

The first command lists accepted fields, required fields, source/dataset pairs and restrictions directly from the compiler. The second lists assets, identities, external entities and declared service relationships. Neither writes a dataset. See the [scenario contract](scenarios.md) for the JSON structure.

Existing internal assets and identities must be reused unless code/inventory changes are explicitly in scope. Scenario JSON can add external entities, not arbitrary internal hosts or accounts. An invented host name as a literal might pass a field-type check but is not automatically a valid asset in the shared world.

## 4. Propose actions and observable evidence

For each action, write its order/time, prerequisites, host/user, intended behavior, supported source/dataset, observation fields, and what the observation cannot prove. Put narrative and intended causality in step descriptions and dependencies; analysts receive only the observations.

For example, file reads followed by Rclone and an outbound flow can support a collection/transfer hypothesis. They cannot prove which file bytes were transferred. A process launch does not establish successful credential theft or defense impairment. A network connection alone does not establish attribution.

Use relative offsets from the chosen start. All steps and observation delays must fit inside the duration. Custom offsets are fixed: increasing duration does not stretch the authored story. A different seed is not a different plot.

## 5. Manually customize the JSON

Copy the [minimal template](../scenarios/templates/minimal.json) or the [larger file-collection example](../scenarios/file-collection.json) into an ignored working directory:

~~~powershell
New-Item -ItemType Directory -Force .\output\my-story-input
Copy-Item .\scenarios\templates\minimal.json .\output\my-story-input\scenario.json
~~~

Open the copy in any text editor. Preserve schema_version 1. JSON has no comments; put rationale in description strings or separate notes.

| Edit | How | Check afterward |
| --- | --- | --- |
| Identity/title | Change id, title and description | Title/description are private truth, not security evidence. |
| Order | Add/remove/reorder steps | IDs are unique; depends_on points only to earlier steps. |
| Timing | Change offset_seconds and optional delay_ms | Every observation stays inside the intended duration. |
| Host/user | Replace inventory references | The named asset/account exists and can plausibly perform the action. |
| Destination | Add an external entity and reference its IP | IDs/IPs are unique and do not collide with context. |
| Evidence | Edit observations and supported fields | Do not invent field names, sensor sources or observed outcomes. |
| Outcome | Change the actual observations and revise notes | A narrative change alone does not create new evidence. |
| Volume | Set target-events in the command | It covers all prescribed observations; remaining records are ordinary activity. |

A concrete first edit: change the template's object/object_path from planning.txt to inventory.csv / D:\Shares\Projects\inventory.csv, move its offset from 300 to 600, and update the private description. That changes the prescribed file-read artifact and time without changing generator code. Adding a new step requires at least one observation, not just prose.

## 6. Validate without generating

~~~powershell
& $python .\validate_scenario.py `
  --scenario-file .\output\my-story-input\scenario.json `
  --seed 42 --host-count 23 --duration-minutes 60 --target-events 1000
~~~

Success reports step/observation counts, the minimum whole-minute duration for the prescribed offsets, and dataset_generated false. Errors identify the invalid input; repair it and rerun. The validator and generator share step/field/reference checks and custom-entity collision handling. Validation does not contact destinations or execute process command strings.

Review source fidelity, installed-software assumptions, account privileges, service ports, sensor coverage and process/session continuity separately. Structural validity is not proof of a possible attack or effective detection.

## 7. Generate and inspect

After reviewing the sequence and settings, use the same values in generation:

~~~powershell
& $python .\create_dataset.py `
  --scenario-file .\output\my-story-input\scenario.json `
  --seed 42 --host-count 23 --start-time '2026-11-10T12:00:00Z' `
  --duration-minutes 60 --target-events 1000 `
  --output-dir .\output\my-story-run-01
Get-Content .\output\my-story-run-01\dataset-manifest.json
Get-Content .\output\my-story-run-01\truth\scenario-truth.json
~~~

Choose a new output directory for every run. Check event_records, planted_records, background_records and source_counts. Spot-check the expected host/user/time/artifact sequence in events/ and compare it with the private answer key. Index only events/*.jsonl using the [README ingest workflow](../README.md#use-the-events-in-splunk).

Reusable reviewed inputs belong in tracked scenarios/ and matching docs/examples/ notes. Unreviewed working inputs and generated datasets belong in ignored output/. Keep the Git revision and generation parameters with reproducible exercises.
