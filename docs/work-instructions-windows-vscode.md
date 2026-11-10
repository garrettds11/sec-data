# Work instructions — Windows + Visual Studio Code

## Goal

Generate and inspect the primary CIM-shaped event dataset, run local tests, and use VS Code for development. Standalone vulnerability and compliance exports remain available for local analysis and optional DynamoDB upload. Generating data is offline; uploading to AWS is a separate action. A `--dry-run` writes no output file but still executes Python locally.

## 1. Open the repository

In PowerShell:

```powershell
cd C:\GitHub\sec-data
git status
git pull --ff-only origin main
code .
```

If you already have a modified local branch or uncommitted changes, review `git status` before switching branches or pulling; do not discard local changes. Install Microsoft's VS Code **Python**, **Python Debugger**, and **Pylance** extensions.

## 2. Select Python 3.12

```powershell
cd C:\GitHub\sec-data
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe --version
```

In VS Code, press **Ctrl+Shift+P** > **Python: Select Interpreter** and select `C:\GitHub\sec-data\.venv\Scripts\python.exe`. Adjust the path if you cloned elsewhere.

No Python packages are required to generate JSON or execute unit tests. Avoid activating PowerShell scripts if your endpoint blocks them: invoking `.venv\Scripts\python.exe` directly works.

## 3. Run unit tests

From the repository root in VS Code's integrated terminal (**Ctrl+`**):

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Expect a final `OK`. The suite checks seeded generation, cross-file story links, the CIM event package, catalog applicability, JSON/JSONL export, historical keys, and uploader input validation. It does not test live Splunk extraction or AWS connectivity and permissions. If a restricted environment denies writes to the default temporary directory, set `TEMP` and `TMP` to a writable workspace directory before running tests.

**VS Code Testing panel:** Click the beaker icon, choose **Configure Python Tests** if prompted, select `unittest`, directory `tests`, pattern `test_*.py`; then **Run All Tests** or debug individual test cases.

## 4. Generate the CIM event package

From the repository root, set the named variables shown in the [README quick start](../README.md#quick-start-generate-a-dataset). Then choose a four-hour window and a new output directory:

```powershell
$durationMinutes = 240
$outputDir = '.\output\reference-4h'
& $python .\create_dataset.py --seed $seed --start-time $startTime `
  --duration-minutes $durationMinutes --target-events $targetEvents `
  --output-dir $outputDir
Get-Content -LiteralPath (Join-Path $outputDir 'dataset-manifest.json')
Get-Content -LiteralPath (Join-Path $outputDir 'events\web-app.jsonl') -TotalCount 2
```

With the README's `$targetEvents` value, the command publishes exactly 10,000 events. `events/*.jsonl` are the only files intended for the analyst event index; `context/` and `truth/` provide reference and validation data. The four-hour setting is explicit; the command-line default remains 60 minutes. See the [dataset guide](dataset.md) for file layout and the [README](../README.md#use-the-events-in-splunk) for ingest instructions. The `output/` directory is ignored by Git. Remove an individual run directory after use to reclaim space.

For a new story, choose CISA-oriented, AI-generated or human-generated content in the [authoring guide](scenario-authoring.md). You can edit any scenario manually or use [AI assistance](ai-authoring.md). Validate with validate_scenario.py before using --scenario-file in the generation command. The same sequence applies to humans and machines; a CISA story also follows the [advisory guide](cisa-scenario-authoring.md).

## 5. Preview standalone finding generators

From the repository root:

```powershell
.\.venv\Scripts\python.exe .\create_vuln_table.py --dry-run --seed 42
.\.venv\Scripts\python.exe .\create_compliance_table.py --dry-run --seed 42
```

Inspect the reported counts and planted cases. With seed 42, the default vulnerability export produces 90 findings on 22 hosts. The compliance export produces 21 findings on four eligible hosts because its catalogs cover Windows Server 2022 and Ubuntu 22.04; the other 19 hosts are **unassessed**, not compliant.

## 6. Debug standalone generators in VS Code

1. Open `create_vuln_table.py` or `create_compliance_table.py`.
2. Place breakpoints in `build_items()`, `assessment()` (compliance), or `main()` by clicking left of a line number.
3. Open **Run and Debug** (**Ctrl+Shift+D**).
4. Create `.vscode/launch.json` if it is not present, with the configurations below.
5. Select **Vulnerability — preview** or **Compliance — preview**, and press **F5**. Inspect `hosts`, `items`, `status`, `actual_value`, and `expected_value` using Variables/Watch. Use **F10** to step over and **F11** to step into.

Sample `.vscode/launch.json` (do not add an upload configuration):

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Vulnerability — preview",
      "type": "debugpy",
      "request": "launch",
      "program": "${workspaceFolder}/create_vuln_table.py",
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "args": ["--dry-run", "--seed", "42"]
    },
    {
      "name": "Compliance — preview",
      "type": "debugpy",
      "request": "launch",
      "program": "${workspaceFolder}/create_compliance_table.py",
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "args": ["--dry-run", "--seed", "42"]
    }
  ]
}
```

## 7. Write standalone findings outside the checkout

For standalone exports, you can write outside the checkout. This example uses a terminal in `C:\code` and references the repository's Python environment and scripts:

```powershell
cd C:\code
C:\GitHub\sec-data\.venv\Scripts\python.exe `
  C:\GitHub\sec-data\create_vuln_table.py `
  --seed 42 --output .\vuln-findings.json

C:\GitHub\sec-data\.venv\Scripts\python.exe `
  C:\GitHub\sec-data\create_compliance_table.py `
  --seed 42 --output .\compliance-findings.json
```

Expected files: `C:\code\vuln-findings.json` and `C:\code\compliance-findings.json`. These are plain JSON arrays. The generators **never** communicate with AWS. The `--output` path is resolved against your terminal's working directory.

Check records from PowerShell:

```powershell
((Get-Content .\vuln-findings.json -Raw | ConvertFrom-Json) | Measure-Object).Count
((Get-Content .\compliance-findings.json -Raw | ConvertFrom-Json) | Measure-Object).Count
```

For reproducibility, pass `--as-of 2026-10-15T12:00:00Z` to either finding generator. The vulnerability generator otherwise uses current UTC time. For large JSONL exports and historical snapshots, follow [Scale and historical exports](scale.md). For the offline recon generator, its truth file, and investigation examples, follow [Offline reconnaissance telemetry](recon.md).

In VS Code, open `create_recon_events.py` and break in `Operation.build()`, `Operation.connection()`, or `generate()`. Inspect `SERVICES`, `PUBLIC_IPS`, `outcome`, `events`, and `manifest`. Run the script with `--dry-run --start-time 2026-10-22T12:00:00Z` while debugging; this avoids creating files. Normal local generation never performs a real scan or AWS operation.

## 8. Optional AWS upload

Do not run this step until you intend to write to DynamoDB and have confirmed authorization, region, IAM rights and costs. From `C:\code`:

```powershell
C:\GitHub\sec-data\.venv\Scripts\python.exe -m pip install boto3
aws configure list-profiles

C:\GitHub\sec-data\.venv\Scripts\python.exe `
  C:\GitHub\sec-data\upload_to_aws.py `
  --dataset vuln --input .\vuln-findings.json --region us-east-1

C:\GitHub\sec-data\.venv\Scripts\python.exe `
  C:\GitHub\sec-data\upload_to_aws.py `
  --dataset compliance --input .\compliance-findings.json --region us-east-1
```

Without `--profile`, select a profile interactively. Review the uploader's **AWS account ID, region, table, record count**, and type `UPLOAD` only after confirming. To specify a known profile add `--profile PROFILE`. Do **not** use `--yes` unless unattended changes are intentional. Repeating an upload upserts matching primary keys (current findings) rather than maintaining scan history.

## 9. Common troubleshooting

| Symptom | Check |
| --- | --- |
| `python` not recognized | Use `.venv\Scripts\python.exe` directly or `py -3.12`. |
| Output directory already exists | Choose a new `--output-dir`; `create_dataset.py` does not overwrite a previous run. |
| `No module named common` | Execute the actual script file from within the checked-out repository (as shown); do not copy only the generator elsewhere. |
| Compliance has few hosts | Current catalogs cover only exact Windows Server 2022 / Ubuntu 22.04 matches. |
| Cannot select test interpreter | VS Code **Python: Select Interpreter**, select the repo venv. |
| `boto3` missing | It is only needed for the uploader; install in the selected venv. |
| No AWS profiles listed | Configure AWS CLI/SSO profile, or use `--profile` where a valid profile already exists. |
| No AWS region | Pass `--region` or configure region on the selected profile. |
| Existing DynamoDB table incompatible | Verify table key schema and dataset-specific secondary indexes; use a different `--table` if needed. |

## 10. Change control

Commit source/catalog/test/doc changes to Git; keep generated data outside the repository or in gitignored `output/`. Run unit tests and dry-runs before opening a PR or merging changes. Never commit real AWS credentials or secrets.
