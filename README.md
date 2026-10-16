# sec-data

Synthetic security datasets for security analytics and AI investigation tests.

## Separate generation from AWS deployment

**Generation never contacts AWS.** Both generators write JSON locally by default:

```powershell
python create_vuln_table.py --output output/vuln-findings.json --seed 42
python create_compliance_table.py --output output/compliance-findings.json --seed 42
```

Use `--dry-run` on either generator to inspect a summary without writing files. The compliance generator also accepts `--as-of 2026-10-15T12:00:00Z` (defaults to a stable time); vulnerability dates reflect the current UTC time and are not byte-for-byte reproducible across days.

**Uploading is a separate, explicit action**, requiring `boto3`, configured AWS CLI profiles, IAM access to DynamoDB and STS, and a confirmed destination:

```powershell
python -m pip install boto3
aws configure list-profiles
python upload_to_aws.py --dataset vuln --input output/vuln-findings.json
python upload_to_aws.py --dataset compliance --input output/compliance-findings.json
```

When `--profile` is omitted, the uploader lists local AWS CLI profiles and asks which to use. The command resolves the AWS account using STS, displays the account, region, table, and record count, and requires typing `UPLOAD` before any DynamoDB write. An explicit `--profile myprofile --region us-east-1 --yes` supports deliberate unattended execution. Without an interactive terminal, a profile must be supplied. The uploader will create missing on-demand tables or upsert records into matching existing tables. No table deletion is supported.

Default tables: `aiwebdemo-vuln-findings` and `aiwebdemo-compliance-findings`, each with `host_name` / `finding_id` primary keys and their dataset-specific secondary indexes.

## Catalog and inventory

Both generators share `common/assets.py`, retaining the existing 23 host definitions and vulnerability generator's seeded host RNG sequence. The compliance catalog in `catalogs/compliance/` contains independently authored, illustrative Windows Server 2022 and Ubuntu 22.04 controls; these are **not official CIS Benchmark text, control identifiers, or certified scan results**. Only exact matching OS versions and applicable roles receive compliance assessments. Statuses and expected/observed values are simulated, not collected from endpoints.

## Testing

```powershell
python -m unittest discover -s tests -v
python create_vuln_table.py --dry-run
python create_compliance_table.py --dry-run
```

The `output/` directory is gitignored to avoid committing generated test data.
