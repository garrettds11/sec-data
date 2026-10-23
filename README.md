# sec-data

Generate **synthetic vulnerability findings**, **CIS-inspired configuration compliance findings**, and **offline reconnaissance/discovery telemetry** for security analytics, AI demos, and testing. This project **does not scan real systems** and does not supply official CIS Benchmark content.

## Quick start (Windows / PowerShell)

Requirements: Windows 10/11, Python **3.12** (the tested/CI target), PowerShell, and Git. VS Code is recommended. See [Windows software requirements](docs/windows-software-requirements.md).

Clone and create a virtual environment:

```powershell
git clone https://github.com/garrettds11/sec-data.git C:\code\Github\sec-data
cd C:\code\Github\sec-data
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

**Generate locally; no AWS access or boto3 required:**

```powershell
cd C:\code
.\Github\sec-data\.venv\Scripts\python.exe .\Github\sec-data\create_vuln_table.py --seed 42 --output .\vuln-findings.json
.\Github\sec-data\.venv\Scripts\python.exe .\Github\sec-data\create_compliance_table.py --seed 42 --output .\compliance-findings.json
```

These commands create `C:\code\vuln-findings.json` and `C:\code\compliance-findings.json`, outside the repository. Or use `--dry-run` to inspect output without writing files. A relative `--output` path is resolved against the **current working directory**, not the script's location.

## Files

| Path | Purpose |
| --- | --- |
| `create_vuln_table.py` | Local vulnerability JSON generator |
| `create_compliance_table.py` | Local compliance JSON generator |
| `create_recon_events.py` | Offline, scenario-driven normalized JSONL telemetry generator |
| `create_story.py` | Linked inventory, entity, finding, recon, DNS, and manifest bundle |
| `upload_to_aws.py` | Optional, separate AWS DynamoDB uploader |
| `common/assets.py` | Shared synthetic inventory of 23 hosts |
| `common/export.py` | Streaming JSON and JSONL output |
| `catalogs/compliance/*.json` | Independently authored illustrative controls |
| `tests/` | Python unittest checks |
| `docs/windows-software-requirements.md` | Supported Windows tooling and optional prerequisites |
| `docs/work-instructions-windows-vscode.md` | End-to-end usage, unit testing and VS Code debugging |
| `docs/scale.md` | Scale, snapshots, catalog extension, and measured benchmarks |
| `docs/recon.md` | Recon schemas, evidence, Splunk investigation examples, and limits |
| `docs/dns.md` | Optional Zeek-shaped DNS JSON export and CIM validation plan |
| `docs/story.md` | Shared world catalog, run bundle, provenance, and current limits |

## Dataset behavior and limitations

- Vulnerability generator uses a seeded pseudo-random inventory, real CVE IDs with synthetic findings, and planted cases. The default seed yields approximately 90 findings on 22 hosts; the exact dates vary by execution time. **Seed alone does not make vulnerability JSON byte-for-byte identical across days.**
- Compliance generator uses the same host inventory but evaluates **only exact OS matches** to the sample Windows Server 2022 and Ubuntu 22.04 LTS catalogs. With seed 42 this produces **21 assessments on 4 hosts**, not coverage of all 23 hosts. Missing OS coverage is **not** a passing compliance result.
- Compliance controls are *independently authored illustrations*: not official CIS recommendation IDs/text, real scan evidence, or a claim of CIS compliance. `synthetic=true` and `assessment_method=simulated` identify generated results.
- Compliance assessments support `--as-of <ISO8601>` (default fixed timestamp) for reproducibility. Both generators support `--seed`, `--output`, and `--dry-run`.
- Both finding generators support `--host-count`, `--findings-per-host`, `--target-records`, `--format jsonl`, and `--snapshots` for larger or historical exports. JSON remains the default. Specify `--as-of` for byte-identical vulnerability output. See [scale guide](docs/scale.md) for count and catalog limits.
- The recon generator writes analyst-facing normalized events separately from a truth manifest. Its optional small Nmap SYN profile is calibrated to a verified public lab capture; other profiles remain uncalibrated. No live Splunk ingestion validation is claimed. See [recon guide](docs/recon.md).
- Use `--zeek-dns-output .\output\dns.log` with the recon generator for separate synthetic Zeek-shaped DNS JSONL. See [DNS guide](docs/dns.md); Splunk CIM mapping still requires an installed add-on test.
- Use `create_story.py --start-time 2026-10-22T12:00:00Z --output-dir .\output\story-42` to export one reproducible linked run. See [story guide](docs/story.md).

## Optional AWS upload (separate operation)

Only `upload_to_aws.py` connects to AWS. Requires `boto3`, a configured AWS CLI profile with valid credentials, DynamoDB permissions, STS GetCallerIdentity, and access to the chosen region. **Uploading creates or upserts DynamoDB items and can incur AWS costs.**

```powershell
.\Github\sec-data\.venv\Scripts\python.exe -m pip install boto3
aws configure list-profiles
.\Github\sec-data\.venv\Scripts\python.exe .\Github\sec-data\upload_to_aws.py --dataset vuln --input .\vuln-findings.json --region us-east-1
.\Github\sec-data\.venv\Scripts\python.exe .\Github\sec-data\upload_to_aws.py --dataset compliance --input .\compliance-findings.json --region us-east-1
```

When `--profile` is omitted in an interactive terminal, the uploader lists available CLI profiles and prompts for one. It displays the resolved AWS account/region/table, and requires typing **UPLOAD** before writing. Provide `--profile PROFILE` explicitly for non-interactive execution; `--yes` deliberately bypasses the upload confirmation. Tables default to `aiwebdemo-vuln-findings` and `aiwebdemo-compliance-findings`, each with dataset-specific secondary indexes. An existing matching table receives upserts; **no history table is maintained**. There is no delete action.

For step-by-step checks, troubleshooting, and VS Code setup, read [Work instructions](docs/work-instructions-windows-vscode.md).

## License

See [LICENSE](LICENSE).
