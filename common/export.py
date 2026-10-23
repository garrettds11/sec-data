"""Bounded-memory JSON/JSONL export shared by the local generators."""
import json
import os
import tempfile
from itertools import islice
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path


def parse_times(values):
    result = []
    for value in values:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("Assessment times must include a timezone")
        result.append(dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))
    if len(result) != len(set(result)) or result != sorted(result):
        raise ValueError("Snapshot times must be unique and in ascending order")
    return result


def json_default(value):
    if isinstance(value, Decimal):
        return float(value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def export_records(path, records, output_format, target_records=None, on_record=None, dry_run=False):
    """Consume a record iterator atomically, with only one record resident at a time."""
    if output_format not in ("json", "jsonl"):
        raise ValueError("--format must be json or jsonl")
    if target_records is not None and target_records < 1:
        raise ValueError("--target-records must be positive")
    target = Path(path)
    temp_path = None
    handle = None
    count = 0
    try:
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=target.parent,
                                                 prefix=f".{target.name}.", suffix=".tmp", delete=False)
            temp_path = Path(handle.name)
            if output_format == "json":
                handle.write("[\n")
        stream = records if target_records is None else islice(records, target_records)
        for record in stream:
            if handle:
                rendered = json.dumps(record, default=json_default, sort_keys=True, separators=(",", ":"))
                if output_format == "json":
                    handle.write((",\n" if count else "") + rendered)
                else:
                    handle.write(rendered + "\n")
            if on_record:
                on_record(record)
            count += 1
        if target_records is not None and count != target_records:
            raise ValueError(f"Requested {target_records} records, but only {count} applicable records exist")
        if count == 0:
            raise ValueError("No applicable records generated")
        if handle:
            if output_format == "json":
                handle.write("\n]\n")
            handle.close()
            os.replace(temp_path, target)
            temp_path = None
        return count
    finally:
        if handle and not handle.closed:
            handle.close()
        if temp_path:
            temp_path.unlink(missing_ok=True)
