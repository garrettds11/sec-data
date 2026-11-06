"""Route observations to modeled sensors and merge them by event time."""

import json
from collections import defaultdict
from contextlib import ExitStack
from heapq import merge
from pathlib import Path

from common.export import export_records

RECON_SENSORS = {
    "enterprise-resolver-01": "resolver-dns.jsonl",
    "web-app-01": "web-app.jsonl",
    "eastwest-fw-01": "eastwest-firewall.jsonl",
    "perimeter-fw-01": "perimeter-firewall.jsonl",
    "endpoint-lab-01": "endpoint-lab.jsonl",
}


def source_name(event):
    original = event["sec_data_source"]
    if original == "recon.jsonl":
        try:
            return RECON_SENSORS[event["dvc"]]
        except KeyError as exc:
            raise ValueError(f"Unrecognized reconnaissance sensor: {event.get('dvc')}") from exc
    return original


def routed(event):
    event["sec_data_source"] = source_name(event)
    return event


def _read(path):
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def _sort_key(event):
    return event["time"], event.get("event_id", "")


def publish_events(publish, scratch, planted, background):
    """Spool each source, then merge its planted and routine records on disk."""
    scratch.mkdir(parents=True, exist_ok=True)
    counts = {"planted": defaultdict(int), "background": defaultdict(int)}
    names = set()
    with ExitStack() as stack:
        handles = {}
        for kind, events in (("planted", planted), ("background", background)):
            for event in events:
                name = source_name(event)
                event["sec_data_source"] = name
                names.add(name)
                key = kind, name
                if key not in handles:
                    handles[key] = stack.enter_context(
                        (scratch / f"{kind}-{name}").open("w", encoding="utf-8", newline="\n"))
                handles[key].write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                counts[kind][name] += 1
    published = {}
    for name in sorted(names):
        streams = []
        for kind in ("planted", "background"):
            path = scratch / f"{kind}-{name}"
            if path.exists():
                streams.append(_read(path))
        # The planted iterator is a small, sorted narrative. The routine iterator
        # is generated in event-time order, so only one row per stream is resident.
        destination = publish / "events" / name
        count = export_records(destination, merge(*streams, key=_sort_key), "jsonl")
        published[name] = count
    return published, {kind: dict(sorted(value.items())) for kind, value in counts.items()}
