# Generated story fixtures

`story-seed42/` is a complete, deterministic output bundle from `create_story.py`.
It contains 43 files (about 380 KiB), including the source records, supporting
inventory, separate generator truth, and a `run-manifest.json` with record counts
and SHA-256 hashes. The fixture is complete so cross-file references and the
manifest can be checked without regenerating it.

Reproduce it from the repository root with Python 3.12. The output directory
must not already exist:

```powershell
py -3.12 .\create_story.py --seed 42 `
  --start-time 2026-10-22T12:00:00Z --duration-minutes 60 `
  --campaign-count 1 --output-dir .\output\story-seed42-check
py -3.12 -m common.story_validation .\tests\fixtures\story-seed42
```

The generated files were independently reproduced with the same parameters;
all 43 files matched byte for byte. The standalone bundle validator passed.

`dns-edge-cases.log` is a separate Zeek-shaped JSONL sample from the same
parameters with `--campaign-count 2`. Its 17 records cover A, AAAA with no
answer, NXDOMAIN, SERVFAIL, CNAME, and an unanswered query followed by a
successful retry. SHA-256:
`c2735e203fd28d495075666b21ea21ef5dac101911f61499c4d416c388a6da0c`.
It is not part of the one-campaign bundle or its manifest.

## Review notes

- The 23 assets, 89 normalized recon events, 8 DNS rows, and the linked
  ingress, authentication, endpoint, data-access, alert, and response records
  pass the repository's chronology, reference, and source-projection checks.
- The source-shaped Zeek JSON and Windows XML projections have no scenario
  labels. The normalized `recon.jsonl` intentionally has a `synthetic` flag;
  use source-shaped files when evaluating add-on parsing. Keep `*-truth.json`,
  `identities.jsonl`, `access-policies.jsonl`, and other generator context out
  of analyst-facing indexes unless an investigation explicitly uses them.
- The one-campaign DNS file does not exercise query-only/timeout and retry
  handling. Use `dns-edge-cases.log` for that parser check.
- The Windows XML files are synthetic event projections, and the Zeek JSON
  records are rendered by this generator, not captured from those products.
  The [static add-on audit](../../docs/addon-parsing-audit.md) finds concrete
  parser-format mismatches in the pinned Zeek, Windows, and Sysmon add-ons.
  Splunk time extraction, field aliases, tags, and CIM data-model membership
  remain unverified. Track live ingestion results in issue #22.
- The response case deliberately treats the public probe as context; it does
  not establish that the public scanner and later operator are the same actor.

For candidate sourcetypes and validation checks, see `docs/dns.md`,
`docs/identity.md`, `docs/endpoint.md`, `docs/ingress.md`,
`docs/data-access.md`, and `docs/response.md`.
