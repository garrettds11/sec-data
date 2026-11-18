"""Check promised indicator values against analyst observations, never context/truth."""

import fnmatch
import json
from pathlib import Path


def load_coverage(path):
    catalog = json.loads(Path(path).read_text(encoding="utf-8"))
    if catalog.get("schema_version") != 1 or not isinstance(catalog.get("scenario_id"), str):
        raise ValueError("Coverage catalog requires schema_version 1 and a scenario_id")
    entries = catalog.get("indicators")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Coverage catalog needs indicator assertions")
    ids = set()
    allowed = {"domain": {"query"}, "ipv4": {"src", "dest", "src_ip", "dest_ip"},
               "sha256": {"file_hash", "process_hash"},
               "sha1": {"file_hash", "process_hash"},
               "ssdeep": {"file_hash_ssdeep"},
               "hostname": {"src", "dest"},
               "md5": {"file_hash", "process_hash"}, "path": {"file_path", "process"}}
    for entry in entries:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(key), str) and entry[key]
                for key in ("id", "source", "kind", "value", "field", "match", "step_id")):
            raise ValueError("Malformed coverage assertion")
        if (entry["id"] in ids or entry["kind"] not in allowed
                or entry["field"] not in allowed[entry["kind"]]
                or entry["match"] not in {"exact", "glob", "basename"}
                or (entry["match"] != "exact" and entry["kind"] != "path")):
            raise ValueError("Invalid/duplicate coverage assertion")
        ids.add(entry["id"])
    return catalog


def _matches(actual, entry):
    if not isinstance(actual, str):
        return False
    if entry["kind"] == "ssdeep":
        return actual == entry["value"]
    actual, expected = actual.casefold(), entry["value"].casefold()
    if entry["match"] == "glob":
        # Windows paths are compared independently of the checker's operating system.
        return fnmatch.fnmatchcase(actual, expected)
    if entry["match"] == "basename":
        return actual.replace("\\", "/").rsplit("/", 1)[-1] == expected
    return actual == expected


def check_coverage(catalog, events):
    """Return every assertion and exact event IDs supporting it, including omissions."""
    entries = catalog["indicators"]
    by_field = {}
    hits = {entry["id"]: [] for entry in entries}
    for entry in entries:
        by_field.setdefault(entry["field"], []).append(entry)
    for event in events:
        for field, candidates in by_field.items():
            if field not in event:
                continue
            for entry in candidates:
                if _matches(event[field], entry):
                    hits[entry["id"]].append({"event_id": event.get("event_id", ""),
                                             "source": event.get("sec_data_source", ""),
                                             "time": event.get("time", ""), "field": field})
    assertions = [{"id": entry["id"], "source": entry["source"],
                   "table": entry.get("table"), "row": entry.get("row"),
                   "kind": entry["kind"], "value": entry["value"],
                   "field": entry["field"], "status": "present" if hits[entry["id"]] else "missing",
                   "event_ids": sorted({hit["event_id"] for hit in hits[entry["id"]]}),
                   "evidence": hits[entry["id"]]} for entry in entries]
    missing = sum(row["status"] == "missing" for row in assertions)
    return {"scenario_id": catalog["scenario_id"], "status": "complete" if missing == 0 else "incomplete",
            "assertion_count": len(entries), "present": len(entries) - missing,
            "missing": missing,
            "unique_indicators": len({(e["kind"], e["value"] if e["kind"] == "ssdeep" else e["value"].casefold()) for e in entries}),
            "scope": catalog.get("scope", "Published-table assertions only; STIX attachment/CSV parity and detection efficacy are not established."),
            "assertions": assertions}


def check_dataset(dataset_dir, coverage_file):
    root = Path(dataset_dir)
    catalog = load_coverage(coverage_file)
    manifest = json.loads((root / "dataset-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("scenario_id") != catalog["scenario_id"]:
        raise ValueError("Dataset scenario_id does not match coverage catalog")
    files = sorted((root / "events").glob("*.jsonl"))
    if not files:
        raise ValueError("Dataset has no events/*.jsonl files")

    def events():
        for path in files:
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    if line.strip():
                        event = json.loads(line)
                        if not isinstance(event, dict) or not all(
                                isinstance(event.get(key), str) and event[key]
                                for key in ("event_id", "time", "sec_data_source")):
                            raise ValueError(f"Malformed analyst observation in {path.name}")
                        yield event
    report = check_coverage(catalog, events())
    report["run_id"] = manifest.get("run_id")
    report["scenario_sha256"] = manifest.get("scenario_sha256")
    return report
