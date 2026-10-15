# sec-data

Synthetic security datasets for testing security analytics and AI investigation workflows.

## Generators

- `create_vuln_table.py`: vulnerability scan findings with illustrative statuses.
- `create_compliance_table.py`: CIS-inspired synthetic configuration assessments, with expected/actual evidence and repeatable seeded outcomes.

Both generators use `common/assets.py` for the same 23 synthetic hosts. OS versions are selected deterministically per seed. The vulnerability generator's existing seeded RNG behavior is preserved.

## Compliance quick start

```shell
python create_compliance_table.py --dry-run --seed 42
python create_compliance_table.py --region us-east-1
python create_compliance_table.py --region us-east-1 --append
python -m unittest discover -s tests -v
```

`--dry-run` does not import boto3 or contact AWS. `--as-of` sets the assessment timestamp (default is a fixed UTC timestamp to make output reproducible). AWS loading requires `pip install boto3` and configured credentials.

DynamoDB table: `aiwebdemo-compliance-findings`. Partition key `host_name`, sort key `finding_id`; secondary indexes `status-lastseen-index` and `control-host-index`. `--append` upserts latest results with the same keys. This MVP does not preserve assessment history.

## Scope and interpretation

Catalogs are in `catalogs/compliance/`. They contain **independently authored illustrative controls**, not official CIS text, machine-readable benchmark files, recommendation IDs, or claims of CIS conformance. Only matching OS versions and applicable roles receive findings. Non-covered OS versions intentionally receive no assessments.

Findings are **simulations, not observations of real endpoint state**. `assessment_method=simulated` and `synthetic=true` make that explicit. Expected and actual values are coherent with their pass/fail status. Seeded scenario rules create consistent planted failures and relative differences between production and development environments. Because the initial scope includes a limited sample catalog, results must not be interpreted as compliance scores for a full benchmark.

The compliance generator uses a fixed default `--as-of` so changing wall-clock time will not change results. Supply another timezone-aware ISO timestamp to label another test run. Only the current posture is retained when upserting to DynamoDB.

## Compatibility

Shared host extraction preserves original host declarations, vendor list, OS options, MAC generation, IP assignments, and the order of pseudo-random calls. The vulnerability generator's AWS table schema and CLI are unchanged.
