# Python version and migration

## Default and coverage

Use the latest patched **Python 3.15**, preferably 64-bit, for new environments. `.python-version` declares `3.15` for tools that read that file. The documented Windows commands explicitly select it with `py -3.15`. The file does not install Python, select the Windows launcher, enforce a runtime version, or migrate a virtual environment by itself.

CI runs the full unit suite and fixed-time vulnerability/compliance dry runs on Python **3.12 and 3.15**, on **Windows and Linux**. Keeping 3.12 in the matrix is a compatibility check, not a recommendation to install an old or unpatched 3.12 build. Other Python branches are not in the matrix.

No generator implementation changes were needed for the transition. Local generation and tests require only the standard library. The optional DynamoDB uploader requires a compatible, maintained `boto3` installation and separate AWS permissions.

## Transition evidence

At the transition, all 57 tests passed on CPython 3.15.2 on Linux. A direct comparison against CPython 3.12.14 used seed `2`, 23 hosts, `2024-11-12T08:00:00Z`, a 120-minute window and 10,000 events per dataset:

| Check | Result |
| --- | --- |
| Reference investigation | All 42 package files byte-identical, including the manifest |
| Black Basta scenario | All 22 package files byte-identical, including context, truth and manifest |
| Black Basta event count | 10,000: 43 prescribed and 9,957 routine observations |
| Black Basta event timestamps | `2024-11-12T08:00:00.000Z` through `2024-11-12T09:59:59.276Z` |
| Current source-story bundle at the checked-in fixture settings | All 43 generated files byte-identical between the two interpreters; the historical snapshot itself predates the current world model |
| Standalone vulnerability/compliance JSON | Byte-identical with the same seed and explicit assessment time |

These are measured checks for those inputs and builds, not a guarantee of identical bytes for every future Python release or input. Refer to the PR's Windows/Linux workflow results for platform validation. Live Splunk ingestion and live AWS uploads are not part of this transition's validation. Historical benchmark documents retain the Python version originally used.

## Migrate an existing Windows checkout

Install an organization-approved, patched Python 3.15 build first, then open a new PowerShell session in the checkout. If a venv is currently activated, deactivate it before proceeding. Stop processes using `.venv`.

Verify the new interpreter:

```powershell
py -3.15 --version
```

Preserve the old environment and create a new one. The backup is kept for restoration to its original `.venv` path; do not run it from its renamed location because virtual environments contain absolute paths.

```powershell
if (Test-Path -LiteralPath '.venv-py312-backup') {
    throw 'A backup already exists. Preserve it and choose a different backup name.'
}

if (Test-Path -LiteralPath '.venv') {
    Move-Item -LiteralPath '.venv' -Destination '.venv-py312-backup' -ErrorAction Stop
}

py -3.15 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python 3.15 environment.' }

$python = '.\.venv\Scripts\python.exe'
& $python --version
& $python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed. Review before generating data.' }

& $python .\validate_scenario.py `
  --scenario-file .\scenarios\cisa\aa24-131a-black-basta.json `
  --seed 2 --host-count 23 --duration-minutes 120 --target-events 10000
if ($LASTEXITCODE -ne 0) { throw 'Scenario validation failed.' }
```

Select `.venv\Scripts\python.exe` again in VS Code. If you use the optional uploader, install its dependency separately into this new environment with `& $python -m pip install boto3`; core generation needs no pip packages. Review any other packages from the old environment instead of copying its `site-packages` directory.

The old Python installation is not patched or removed by this process. Remove an obsolete interpreter only after checking other applications and applying your organization's software lifecycle process.

Installing a newer interpreter alone does not update an existing venv. A venv also does not sandbox vulnerabilities in its interpreter. Keep the selected Python build patched through the approved distribution channel.

For generation, reuse the reviewed scenario and settings from its [worked example](examples/aa24-131a-black-basta-notes.md), and choose a new output directory. Re-ingesting existing records into Splunk creates duplicates; migrating Python does not require re-ingesting previous datasets.
