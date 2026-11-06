"""Validate and compile an authored investigation into CIM-shaped observations."""

import hashlib
import ipaddress
import json
from datetime import timedelta, timezone
from pathlib import Path

from common.background import DATASETS, validate_mix

SCHEMA_VERSION = 1
SOURCE_DATASETS = {
    **{name: {dataset} for name, dataset in DATASETS.items()},
    "perimeter-firewall.jsonl": {"Network_Traffic.All_Traffic"},
    "endpoint-lab.jsonl": {"Endpoint.Processes"},
    "ingress-firewall.jsonl": {"Network_Traffic.All_Traffic"},
    "ingress-zeek-conn.jsonl": {"Network_Traffic.All_Traffic"},
    "ingress-zeek-http.jsonl": {"Web.Web"},
    "edge-proxy.jsonl": {"Web.Web"},
    "response-firewall.jsonl": {"Network_Traffic.All_Traffic"},
    "vulnerability.jsonl": {"Vulnerabilities.Vulnerabilities"},
    "vulnerability-followup.jsonl": {"Vulnerabilities.Vulnerabilities"},
}
SOURCE_DATASETS["sysmon.jsonl"] = {
    "Endpoint.Processes", "Endpoint.Filesystem", "Endpoint.Registry",
    "Network_Traffic.All_Traffic",
}
SOURCE_DATASETS["windows-security.jsonl"] = {
    "Authentication.Authentication", "Change.All_Changes",
}
REQUIRED = {
    "Network_Resolution.DNS": {"src", "dest", "query", "query_type", "answer"},
    "Authentication.Authentication": {"src", "dest", "user", "action"},
    "Network_Traffic.All_Traffic": {"src", "dest", "dest_port", "action"},
    "Web.Web": {"src", "dest", "url", "http_method", "status"},
    "Endpoint.Processes": {"dest", "user", "process", "process_id"},
    "Endpoint.Filesystem": {"dest", "user", "file_path", "action"},
    "Endpoint.Registry": {"dest", "user", "registry_path", "action"},
    "Data_Access.Data_Access": {"dest", "user", "object", "object_path", "action"},
    "Change.All_Changes": {"dest", "user", "action", "object"},
    "Vulnerabilities.Vulnerabilities": {"dest", "signature", "severity"},
}
RESERVED = {"time", "event_id", "session_id", "synthetic", "sec_data_source",
            "sec_data_cim_dataset", "scenario_id", "step_id"}
FORBIDDEN = {"attack", "attacker", "malicious", "compromised", "ground_truth",
             "is_malicious", "truth", "narrative"}
STRING_FIELDS = {
    "access_reason", "access_result", "action", "app", "asset_id", "category",
    "change_id", "connection_result", "connection_state", "cve", "description",
    "dest", "dest_ip", "dvc", "file_path", "finding_id", "http_method",
    "message_type", "object", "object_category", "object_path", "parent_process",
    "probe_type", "process", "process_cmdline", "process_guid", "query",
    "query_type", "reason", "record_type", "registry_path",
    "registry_value_data", "reply_code", "requested_action", "rule",
    "severity", "signature", "src", "src_nt_domain", "src_user", "target_ip",
    "transport", "url", "user", "vendor_product",
}
INTEGER_FIELDS = {
    "answer_count", "bytes", "bytes_in", "bytes_out", "dest_port",
    "packets", "parent_process_id", "process_id", "query_count",
    "reply_code_id", "src_port", "transaction_id",
}
NUMBER_FIELDS = {"cvss", "duration", "response_time"}
ARRAY_FIELDS = {"answer": str, "ttl": int}


def _validate_fields(fields, dataset):
    for name, value in fields.items():
        if name in STRING_FIELDS:
            valid = isinstance(value, str) and bool(value)
        elif name in INTEGER_FIELDS:
            valid = type(value) is int and value >= 0
        elif name in NUMBER_FIELDS:
            valid = type(value) in {int, float} and value >= 0
        elif name in {"signature_id", "status"}:
            valid = type(value) in {str, int} and bool(value)
        elif name in ARRAY_FIELDS:
            valid = isinstance(value, list) and all(
                type(item) is ARRAY_FIELDS[name] for item in value)
        else:
            raise ValueError(f"Unsupported scenario event field: {name}")
        if not valid:
            raise ValueError(f"Invalid value for scenario event field: {name}")
    if all(key in fields for key in ("bytes", "bytes_in", "bytes_out")):
        if fields["bytes"] != fields["bytes_in"] + fields["bytes_out"]:
            raise ValueError("Network bytes must equal bytes_in + bytes_out")
    if dataset == "Authentication.Authentication" and fields["action"] not in {
            "success", "failure"}:
        raise ValueError("Authentication action must be success or failure")
    if dataset == "Network_Traffic.All_Traffic" and fields["action"] not in {
            "allowed", "blocked"}:
        raise ValueError("Network action must be allowed or blocked")
    if dataset == "Network_Resolution.DNS" and any(
            type(answer) is not str for answer in fields["answer"]):
        raise ValueError("DNS answers must be strings")


def _keys(value, required, optional, where):
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError(f"{where} requires {sorted(required)} and permits only "
                         f"{sorted(required | optional)}")


def _digest(*parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]


def _resolve(value, catalogs):
    if isinstance(value, dict):
        _keys(value, {"ref"}, set(), "Reference")
        ref = value["ref"]
        if not isinstance(ref, str) or ref.count(":") != 2:
            raise ValueError(f"Invalid reference: {ref}")
        kind, name, field = ref.split(":")
        try:
            return catalogs[kind][name][field]
        except KeyError as exc:
            raise ValueError(f"Unknown scenario reference: {ref}") from exc
    if isinstance(value, list):
        return [_resolve(item, catalogs) for item in value]
    if value is None or type(value) not in {str, int, float, bool}:
        raise ValueError("Scenario fields require JSON scalar, list, or inventory reference")
    return value


def load_scenario(path):
    """Read a strict, versioned JSON input suitable for machine authoring."""
    spec = json.loads(Path(path).read_text(encoding="utf-8"))
    _keys(spec, {"schema_version", "id", "title", "steps"},
          {"description", "entities", "background_mix"}, "Scenario")
    if type(spec["schema_version"]) is not int or spec["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Unsupported scenario schema_version")
    if not all(isinstance(spec[key], str) and spec[key].strip()
               for key in ("id", "title")):
        raise ValueError("Scenario id and title must be nonempty strings")
    if "description" in spec and not isinstance(spec["description"], str):
        raise ValueError("Scenario description must be a string")
    if not isinstance(spec["steps"], list) or not spec["steps"]:
        raise ValueError("Scenario needs at least one step")
    if "background_mix" in spec:
        validate_mix(spec["background_mix"])
    entities = spec.get("entities", [])
    if not isinstance(entities, list):
        raise ValueError("Scenario entities must be a list")
    ids, addresses = set(), set()
    for item in entities:
        _keys(item, {"entity_id", "name", "ip", "role"},
              {"kind", "authorized"}, "Scenario entity")
        if not all(isinstance(item[key], str) and item[key] for key in item):
            raise ValueError("Scenario entity values must be nonempty strings")
        if item.get("kind", "external_service") not in {
                "external_service", "external_host"} or type(
                item.get("authorized", False)) is not bool:
            raise ValueError("Scenario entities must be external hosts or services")
        ipaddress.ip_address(item["ip"])
        if item["entity_id"] in ids or item["ip"] in addresses:
            raise ValueError("Duplicate scenario entity ID or IP")
        ids.add(item["entity_id"])
        addresses.add(item["ip"])
    return spec


def compile_scenario(spec, start, duration_minutes, assets, entities, identities, run_id):
    """Return observations and private truth; validate order and inventory links."""
    catalogs = {
        "asset": {row["short_name"]: row for row in assets},
        "entity": {row["entity_id"]: row for row in entities},
        "identity": {row["identity_id"]: row for row in identities},
    }
    seen, events, truth = {}, [], []
    for step in spec["steps"]:
        _keys(step, {"id", "offset_seconds", "observations"},
              {"description", "depends_on"}, "Scenario step")
        sid, offset = step["id"], step["offset_seconds"]
        if not isinstance(sid, str) or not sid or sid in seen:
            raise ValueError("Scenario step IDs must be unique nonempty strings")
        if (type(offset) not in {int, float} or not 0 <= offset < duration_minutes * 60
                or (seen and offset < max(seen.values()))):
            raise ValueError(f"Step {sid} has an out-of-order or out-of-window offset")
        parents = step.get("depends_on", [])
        if (not isinstance(parents, list) or any(
                not isinstance(parent, str) for parent in parents)
                or len(set(parents)) != len(parents) or any(
                    parent not in seen for parent in parents)):
            raise ValueError(f"Step {sid} depends on a missing or later step")
        observations = step["observations"]
        if not isinstance(observations, list) or not observations:
            raise ValueError(f"Step {sid} needs observations")
        event_ids = []
        for position, observation in enumerate(observations):
            _keys(observation, {"source", "dataset", "fields"},
                  {"delay_ms"}, "Scenario observation")
            source, dataset = observation["source"], observation["dataset"]
            if source not in SOURCE_DATASETS or dataset not in SOURCE_DATASETS[source]:
                raise ValueError(f"Unsupported source/dataset pair: {source} / {dataset}")
            fields = observation["fields"]
            if not isinstance(fields, dict) or not all(
                    isinstance(key, str) and key.isidentifier() for key in fields):
                raise ValueError("Observation fields must be a JSON object with field names")
            if (fields.keys() & RESERVED or fields.keys() & FORBIDDEN
                    or any(key.startswith("sec_data_") for key in fields)):
                raise ValueError("Observation contains reserved or truth-only fields")
            resolved = {key: _resolve(value, catalogs) for key, value in fields.items()}
            if not REQUIRED[dataset] <= resolved.keys():
                raise ValueError(f"{source} missing fields: {sorted(REQUIRED[dataset] - resolved.keys())}")
            _validate_fields(resolved, dataset)
            delay = observation.get("delay_ms", position)
            if type(delay) is not int or delay < 0 or offset * 1000 + delay >= duration_minutes * 60000:
                raise ValueError(f"Observation in {sid} has invalid delay_ms")
            event_id = _digest(run_id, sid, position)
            event_ids.append(event_id)
            event = {
                **resolved,
                "time": (start + timedelta(seconds=offset, milliseconds=delay))
                        .astimezone(timezone.utc).isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z"),
                "synthetic": True, "sec_data_source": source,
                "sec_data_cim_dataset": dataset, "event_id": event_id,
                "session_id": _digest(run_id, sid, "session"),
            }
            if dataset == "Change.All_Changes":
                event["sec_data_cim_subdataset"] = "Account_Management"
            events.append(event)
        truth.append({"step_id": sid, "offset_seconds": offset,
                      "description": step.get("description", ""),
                      "depends_on": parents, "event_ids": event_ids})
        seen[sid] = offset
    events.sort(key=lambda event: (event["time"], event["event_id"]))
    return events, truth
