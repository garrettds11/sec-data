#!/usr/bin/env python3
"""Project an existing synthetic story bundle into CIM-shaped JSONL files."""

import argparse
import hashlib
import json
from pathlib import Path

from common.cim import CIM_VERSION, SOURCES, project


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def export_file(source, input_file, output_file):
    """Project one JSONL generator output, including standalone recon/vulnerability."""
    if source not in SOURCES:
        raise ValueError(f"Unsupported CIM source: {source}")
    path = Path(input_file).resolve()
    target = Path(output_file).resolve()
    if path == target or target.exists():
        raise ValueError("CIM output must be a new file distinct from the source")
    if not path.is_file():
        raise ValueError(f"Source file does not exist: {path}")
    target.parent.mkdir(parents=True, exist_ok=True)
    counts = {"source_records": 0, "cim_records": 0, "unmapped_records": 0}
    try:
        with path.open(encoding="utf-8") as inp, target.open("w", encoding="utf-8", newline="\n") as out:
            for number, line in enumerate(inp, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("Expected one JSON object per line; generate with --format jsonl")
                    event = project(source, row)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"{path.name}:{number}: {exc}") from exc
                counts["source_records"] += 1
                if event is None:
                    counts["unmapped_records"] += 1
                    continue
                out.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                counts["cim_records"] += 1
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"source": source, "source_sha256": _sha256(path),
            "sha256": _sha256(target), **counts}


def export_cim(story_dir, output_dir):
    story = Path(story_dir).resolve()
    output = Path(output_dir).resolve()
    if not story.is_dir():
        raise ValueError(f"Story directory does not exist: {story}")
    if output.exists() or output == story or story in output.parents:
        raise ValueError("CIM output must be a new directory outside the story")
    output.mkdir(parents=True)
    files = {}
    totals = {"source_records": 0, "cim_records": 0, "unmapped_records": 0}
    for source in SOURCES:
        path = story / source
        if not path.exists():
            continue
        name = source.removesuffix(".jsonl").removesuffix(".log") + ".cim.jsonl"
        target = output / name
        files[name] = export_file(source, path, target)
        for key in totals:
            totals[key] += files[name][key]
    if not files:
        output.rmdir()
        raise ValueError("Story has no supported observation files")
    manifest = {"cim_reference_version": CIM_VERSION, "projection": "sec-data CIM-shaped fields",
                "splunk_data_model_validation": "not_performed", "files": files, **totals,
                "excluded": ["assets, entities, relationships, identities, policies and scenario truth",
                             "compliance assessment snapshots (no direct CIM event mapping)",
                             "unmapped observation subtypes are counted per source"]}
    (output / "cim-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                               encoding="utf-8", newline="\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--story-dir", help="Existing story bundle")
    source.add_argument("--input-file", help="One existing JSONL generator output")
    parser.add_argument("--output-dir", help="New directory for a story projection")
    parser.add_argument("--output-file", help="New JSONL file for a single projection")
    parser.add_argument("--source", choices=SOURCES, help="Original source filename for --input-file")
    args = parser.parse_args()
    try:
        if args.story_dir:
            if not args.output_dir or args.output_file or args.source:
                raise ValueError("--story-dir requires --output-dir only")
            manifest = export_cim(args.story_dir, args.output_dir)
            print(f"Projected {manifest['cim_records']} of {manifest['source_records']} observations "
                  f"({manifest['unmapped_records']} unmapped) to {Path(args.output_dir).resolve()}")
        else:
            if not args.output_file or not args.source or args.output_dir:
                raise ValueError("--input-file requires --source and --output-file")
            result = export_file(args.source, args.input_file, args.output_file)
            print(f"Projected {result['cim_records']} of {result['source_records']} observations "
                  f"to {Path(args.output_file).resolve()}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
