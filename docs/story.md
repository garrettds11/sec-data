# Linked synthetic run bundle

`create_story.py` exports a consistent **current-state foundation** before the event stream: internal assets, non-inventory entities, DNS/service/public-exposure relationships, baseline findings, then recon activity. It uses the same seed and host inventory as the standalone generators. It does not contact AWS, scan a network, or require Splunk.

```powershell
python .\create_story.py --seed 42 `
  --start-time 2026-10-22T12:00:00Z `
  --duration-minutes 60 --campaign-count 1 `
  --output-dir .\output\story-42
```

The output directory must be new. A failed run cleans its staging directory; a successful run publishes the complete directory. `run-manifest.json` records the seed, times, host count, generator versions, recipe source/catalog checksums, per-file counts and SHA-256 hashes, and a run ID derived from those inputs. Repeating the run with identical inputs and recipe produces byte-identical files. Larger inventories stream through the export; recon currently involves the first 23 hosts.

| File | Meaning |
| --- | --- |
| `assets.jsonl` | Stable `asset_id`, host identity, address, segment, role, OS, and exposure |
| `entities.jsonl` | Stable IDs for the external scanner, approved scanner, and enterprise resolver |
| `relationships.jsonl` | Stable DNS A, modeled TCP service, and public-exposure edges |
| `vulnerability.jsonl`, `compliance.jsonl` | Baseline assessments one minute before activity, with bundle `asset_id` |
| `recon.jsonl`, `dns.log` | Normalized recon observations and optional Zeek-shaped DNS view |
| `timeline.jsonl`, `recon-truth.json` | Generator-only plan, causal links, authorization, and answer key |
| `run-manifest.json` | Run inputs, recipe hashes, output hashes, and counts |

Keep `timeline.jsonl` and `recon-truth.json` outside analyst-facing indexes. Raw event rows retain their source-owned schemas; stable asset/entity references and causal links live in the separate truth data. The recon operation manifest now identifies its source asset/entity and target asset IDs, and the bundle validates these references before publication.

The bundled vulnerability export keeps only local findings or findings on services that the current world catalog models on that host role. Its manifest counts filtered findings. The standalone vulnerability generator is unchanged. This prevents a bundled finding from claiming an exposed TCP service that the bundled network model says is absent. The modeled service catalog remains intentionally small; it does not describe every possible enterprise service.

This bundle is a foundation for [the shared world-model issue](https://github.com/garrettds11/sec-data/issues/7). The four recon operations remain independent scenarios; the bundle does not claim they form one historical intrusion. Time-varying asset state, identity/authentication, endpoint activity, data access, containment, and remediation are future layers. Splunk CIM validation is source-specific and is not implied by this bundle; see [DNS validation](dns.md).
