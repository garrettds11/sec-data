# Scale and historical exports

## Linked CIM event volume

The primary `create_dataset.py` command accepts `--target-events N` for an exact published event count. The reference story has a planted minimum that rises with additional campaigns; a tailored scenario instead uses the number of observations in its JSON file. The remaining count consists of routine web, file, ingress, and egress sessions linked by session ID and inventory assets. Events from both origins are merged by event time into source-specific files. The [README volume example](../README.md#choose-a-volume) shows how to set `$targetEvents` and a new `$outputDir` for a million-event run.

The [dataset guide](dataset.md#time-scale-and-interpretation) records the current reference package's measured event bytes. The earlier v0.1.0 design measured 42,520,967 bytes for 100,000 events, but its single background source and event mix differ, so that figure is not a measurement of the current layout. The million-event command's full disk-write time and Splunk ingest behavior have not been measured. Read the actual event byte total from `dataset-manifest.json` before indexing against a daily license limit. During generation, source spools and atomic output files temporarily use more disk space than the final package; allow roughly three times the expected event bytes.

## Standalone finding volume

The finding generators use the Python standard library, with Python 3.15 as the default for new environments and CI coverage for 3.12 and 3.15. Historical measurements below retain the interpreter version actually used. The first 23 asset identities and default seeded behavior are preserved. Additional assets use unique `synthetic-*` names, locally administered MAC addresses, and private IPs starting at `10.100.0.1`. Both generators use the same inventory for the same seed and host count. Capacity is validated before generation.

```powershell
python .\create_vuln_table.py --seed 42 --as-of 2026-10-15T12:00:00Z `
  --host-count 3000 --target-records 10000 --format jsonl `
  --output .\output\vuln-10k.jsonl
python .\create_compliance_table.py --seed 42 --as-of 2026-10-15T12:00:00Z `
  --host-count 3000 --format jsonl --output .\output\compliance.jsonl
```

`--target-records` exports exactly the requested number of applicable records or fails and leaves the previous output untouched. It takes records in inventory order, so a small target relative to host count concentrates on early hosts. `--findings-per-host N` requires N eligible findings on each participating host and reports a capacity error otherwise. Compliance skips hosts without an applicable OS/role catalog; these hosts are **unassessed**, not compliant. `--catalog-dir` selects a directory of illustrative compliance catalogs. The vulnerability generator accepts `--additional-catalog` with a JSON list of project-owned `SYNTH-` profiles; see `catalogs/vulnerability/illustrative.json` for the required fields. These are clearly identified synthetic fixtures, not real CVEs or scanner detections. The built-in catalogs still cap findings per host; no records are duplicated to meet a count.

The JSONL writer holds one host's findings at a time and replaces an output atomically after success. JSON array output uses the same streaming writer. Inventory generation is replayed from the seed to preserve the original vulnerability RNG sequence without holding all hosts in memory. Output rows are ordered by snapshot, asset, and catalog. `--dry-run` traverses the same stream and reports actual counts without writing files.

For history, pass ordered distinct ISO 8601 times with timezones:

```powershell
python .\create_vuln_table.py --seed 42 `
  --snapshots 2026-10-15T12:00:00Z 2026-10-22T12:00:00Z `
  --format jsonl --output .\output\vuln-history.jsonl
```

Multi-snapshot rows have `snapshot_id`, `base_finding_id`, and a `finding_id` suffixed with the assessment time, so historical keys stay distinct. A deterministic subset of simulated statuses changes between snapshots. Single-snapshot records retain the existing keys. The optional AWS uploader accepts JSONL and `--history`, which adds the generated `assessment_id` (or `last_seen` for older files) to single-snapshot keys before upload. Its default single-snapshot mode still upserts by `(host_name, finding_id)`. Uploading is a separate explicit operation. The uploader checks duplicate keys before any AWS write using a temporary SQLite database beside the input file. JSONL is then streamed during upload; JSON arrays still require memory for parsing.

## Measured generation and serialization

The command below counts exact UTF-8 JSONL bytes while generating and serializing records, without writing a file. It reports process peak working set. Benchmark host: Windows, Intel64 Family 6 Model 154, 12 logical processors, 38,324,940,800 bytes physical memory reported by Windows; Python 3.12.6, seed 42, assessment time `2026-10-15T12:00:00Z`. These are measurements from this run, not hardware-normalized capacity claims.

```powershell
python .\tools\benchmark_scale.py --dataset vuln --records 100000 --host-count 30000
```

| Records | Configured hosts | Elapsed | Peak process memory | Serialized JSONL bytes |
| ---: | ---: | ---: | ---: | ---: |
| 10,000 | 3,000 | 0.302 s | 19,918,848 | 11,901,030 |
| 100,000 | 30,000 | 4.004 s | 20,262,912 | 119,118,808 |
| 1,000,000 | 300,000 | 86.453 s | 20,197,376 | 1,191,893,252 |

Disk write time, filesystem effects, and AWS upload time are excluded. The 1,000,000-record timing was markedly slower per record than the smaller runs, so do not extrapolate throughput from the first two rows. For actual export, provision enough disk space for the output and its temporary file during atomic replacement.
