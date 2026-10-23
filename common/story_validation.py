"""Validate the cross-file contract of a linked synthetic story bundle."""

import argparse
import hashlib
import json
from itertools import zip_longest
from pathlib import Path

from common.zeek_dns import render_dns
from common.identity import render_windows_xml
from common.world import iter_assets, iter_entities, iter_relationships


def rows(path):
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)


def require(condition, message):
    if not condition:
        raise ValueError(f"Invalid story bundle: {message}")


def validate_identity_bundle(root, truth, assets, entities):
    identity_truth = json.loads((root / "identity-truth.json").read_text(encoding="utf-8"))
    require(identity_truth["run_id"] == truth["run_id"], "identity run ID differs")
    identities = {row["identity_id"]: row for row in rows(root / "identities.jsonl")}
    policies = {row["policy_id"]: row for row in rows(root / "access-policies.jsonl")}
    require(len(identities) == 4 and len({r["account"] for r in identities.values()}) == 4,
            "identity catalog has duplicate or missing accounts")
    require(all(p["identity_id"] in identities and p["asset_id"] in assets
                for p in policies.values()), "access policy reference is missing")
    require(len(policies) == 5, "access policy ID is duplicate or missing")
    web = {row["request_id"]: row for row in rows(root / "web-auth.jsonl")}
    windows = {}
    for row in rows(root / "windows-security.jsonl"):
        eid = f"windows-{row['Computer'].split('.')[0]}-{row['EventRecordID']}"
        require(eid not in windows, "duplicate Windows record ID")
        windows[eid] = row
    with (root / "windows-security.xml").open(encoding="utf-8") as handle:
        for expected, actual in zip_longest((render_windows_xml(row) for row in windows.values()),
                                             (line.rstrip("\r\n") for line in handle)):
            require(expected == actual, "Windows XML view diverges from JSON projection")
    require(len(web) == 6 and len(windows) == 6,
            "identity source event count differs")
    interactions = {item["event_id"]: item for item in identity_truth["interactions"]}
    require(len(interactions) == len(web) + len(windows),
            "duplicate or missing identity interaction")
    for eid, item in interactions.items():
        require(item["identity_id"] in identities and item["asset_id"] in assets,
                "identity interaction reference is missing")
        if item["source"] == "web-auth":
            require(eid in web and item["at"] == web[eid]["time"],
                    "web authentication event differs from truth")
            require(web[eid]["server_name"] == assets[item["asset_id"]]["fqdn"],
                    "web authentication target differs")
            require(web[eid]["account"] == identities[item["identity_id"]]["account"],
                    "web account differs from identity")
            if web[eid]["event"] == "login":
                require(web[eid]["outcome"] == item["outcome"] and
                        web[eid]["client_ip"] == item["source_ip"],
                        "web login differs from truth")
        elif item["source"] == "windows-security":
            require(eid in windows and item["at"] == windows[eid]["TimeCreated"],
                    "Windows event differs from truth")
            require(windows[eid]["Computer"] == assets[item["asset_id"]]["fqdn"],
                    "Windows event target differs")
            if windows[eid]["EventCode"] in (4624, 4625):
                require(windows[eid]["TargetUserName"] ==
                        identities[item["identity_id"]]["account"].split("\\")[1],
                        "Windows account differs from identity")
                if "source_asset_id" in item:
                    require(windows[eid]["IpAddress"] ==
                            assets[item["source_asset_id"]]["ip"],
                            "Windows source address differs")
                else:
                    require(windows[eid]["LogonType"] == 5 and "IpAddress" not in windows[eid],
                            "service logon has a network source")
                require(item["outcome"] ==
                        ("success" if windows[eid]["EventCode"] == 4624 else "failure"),
                        "Windows logon result differs")
        else:
            raise ValueError("Invalid story bundle: unknown identity source")
        if "policy_id" in item:
            policy = policies.get(item["policy_id"])
            require(policy is not None and policy["identity_id"] == item["identity_id"] and
                    policy["asset_id"] == item["asset_id"] and
                    policy["valid_from"] <= item["at"] and
                    (policy["valid_until"] is None or item["at"] < policy["valid_until"]),
                    "identity interaction violates policy interval")
        if "source_asset_id" in item:
            require(item["source_asset_id"] in assets, "identity source asset is missing")
        if "source_entity_id" in item:
            require(item["source_entity_id"] in entities and
                    item["source_ip"] == entities[item["source_entity_id"]]["ip"],
                    "identity source entity differs")
        if "related_operation_id" in item:
            operation = next((op for op in truth["operations"]
                              if op["operation_id"] == item["related_operation_id"]), None)
            require(operation is not None and operation["start_time"] <= item["at"] and
                    operation["source_ref"] == {"entity_id": item["source_entity_id"]},
                    "related recon operation differs")
        if "caused_by" in item and item["caused_by"] in interactions:
            require(interactions[item["caused_by"]]["at"] <= item["at"],
                    "identity causal parent occurs later")
    require(set(web) | set(windows) == set(interactions), "unowned identity event")
    sessions = {row["session_id"]: row for row in identity_truth["sessions"]}
    require(len(sessions) == len(identity_truth["sessions"]), "duplicate session ID")
    for sid, session in sessions.items():
        require(session["identity_id"] in identities and session["asset_id"] in assets,
                "session reference is missing")
        require(any(item.get("session_id") == sid and item.get("outcome") == "success" and
                    item["at"] == session["started_at"] for item in interactions.values()),
                "session has no matching successful authentication")
        if "linked_recon_operation_id" in session:
            operation = next((op for op in truth["operations"]
                              if op["operation_id"] == session["linked_recon_operation_id"]), None)
            require(operation is not None and session["started_at"] < operation["start_time"] and
                    operation["source_ref"] == {"asset_id": session["asset_id"]},
                    "recon operation is not preceded by linked session")
    changes = {row["change_id"]: row for row in rows(root / "identity-state.jsonl")}
    require(changes == {row["change_id"]: row for row in identity_truth["state_changes"]},
            "identity state differs from truth")
    lockout = next(row for row in changes.values() if row["kind"] == "app_lockout")
    grant = next(row for row in changes.values() if row["kind"] == "group_membership")
    require(lockout["identity_id"] in identities and lockout["asset_id"] in assets and
            lockout["effective_at"] < lockout["expires_at"], "invalid app lockout")
    failures = [row for row in web.values() if row["event"] == "login" and
                row["outcome"] == "failure" and row["reason"] == "invalid_password" and
                row["time"] <= lockout["effective_at"]]
    require(len(failures) == lockout["failure_threshold"] and
            max(row["time"] for row in failures) == lockout["effective_at"],
            "lockout does not follow the failed attempts")
    locked = [row for row in web.values() if row["event"] == "login" and
              row["reason"] == "account_locked"]
    require(len(locked) == 1 and lockout["effective_at"] < locked[0]["time"] < lockout["expires_at"],
            "locked attempt falls outside lockout")
    success = [row for row in web.values() if row["event"] == "login" and
               row["outcome"] == "success"]
    require(len(success) == 1 and success[0]["time"] > lockout["expires_at"] and
            success[0]["mfa_result"] == "passed" and
            success[0]["client_ip"] == assets[
                sessions[interactions[success[0]["request_id"]]["session_id"]]["source_asset_id"]]["ip"],
            "web success violates lockout, source, or MFA policy")
    require(grant["identity_id"] in identities and grant["actor_identity_id"] in identities and
            grant["caused_by_session_id"] in sessions and grant["event_id"] in windows and
            grant["effective_at"] == windows[grant["event_id"]]["TimeCreated"] and
            sessions[grant["caused_by_session_id"]]["started_at"] < grant["effective_at"] and
            grant["group"] == policies["policy-file-operator"]["required_group"],
            "group grant lacks authorized preceding session")
    admin_logon = next(item for item in interactions.values() if
                       item.get("session_id") == grant["caused_by_session_id"] and
                       item.get("outcome") == "success")
    require(windows[grant["event_id"]]["SubjectLogonId"] ==
            windows[admin_logon["event_id"]]["TargetLogonId"] and
            windows[grant["event_id"]]["SubjectUserName"] == "admin" and
            windows[grant["event_id"]]["EventCode"] == 4728,
            "group grant does not match Windows admin session")
    operator_windows = [item for item in interactions.values() if
                        item["identity_id"] == grant["identity_id"] and
                        item["source"] == "windows-security" and item.get("policy_id") == "policy-file-operator"]
    require(len(operator_windows) == 2 and
            any(item["at"] < grant["effective_at"] and item["outcome"] == "failure" and
                windows[item["event_id"]]["EventCode"] == 4625 and
                windows[item["event_id"]]["Status"] == "0xC000015B" for item in operator_windows) and
            any(item["at"] > grant["effective_at"] and item["outcome"] == "success" and
                windows[item["event_id"]]["EventCode"] == 4624 for item in operator_windows),
            "operator logon does not follow privilege state")
    return len(identities), len(interactions), len(changes)


def validate_bundle(path, truth):
    root = Path(path)
    seed = truth["seed"]
    asset_count = sum(1 for _ in rows(root / "assets.jsonl"))
    require(asset_count > 0, "empty asset catalog")
    assets = {}
    for expected, actual in zip_longest(iter_assets(seed, asset_count), rows(root / "assets.jsonl")):
        require(expected == actual, "asset catalog diverges from seeded inventory")
        if len(assets) < 23:
            assets[actual["asset_id"]] = actual
    entities = {row["entity_id"]: row for row in rows(root / "entities.jsonl")}
    require(list(entities.values()) == list(iter_entities()), "entity catalog diverges")
    for expected, actual in zip_longest(iter_relationships(seed, asset_count),
                                         rows(root / "relationships.jsonl")):
        require(expected == actual, "relationship catalog diverges")

    def valid_asset_id(value):
        return (isinstance(value, str) and value.startswith("asset-") and
                value[6:].isdigit() and 0 <= int(value[6:]) < asset_count)

    event_times = {}
    dns_count = 0
    for event in rows(root / "recon.jsonl"):
        eid = event["event_id"]
        require(eid not in event_times, "duplicate recon event ID")
        require(event["timestamp"] <= event["collected_at"], "collection predates event")
        event_times[eid] = event["timestamp"]
        if event["event_type"] == "dns":
            dns_count += 1
    for operation in truth["operations"]:
        source = operation["source_ref"]
        require(source.get("asset_id") in assets or source.get("entity_id") in entities,
                "operation source is missing")
        for eid in operation["event_ids"]:
            require(eid in event_times, "operation event is missing")
            require(operation["start_time"] <= event_times[eid] <= operation["last_observation_at"],
                    "event falls outside operation")
        for link in operation["interaction_links"]:
            eid = link["event_id"]
            require(eid in event_times, "interaction event is missing")
            require("target_asset_id" not in link or link["target_asset_id"] in assets,
                    "interaction target is missing")
            for field in ("caused_by", "resolved_by", "retry_of"):
                if field in link:
                    parent = link[field]
                    require(parent in event_times, "interaction parent is missing")
                    require(event_times[parent] <= event_times[eid],
                            "interaction parent occurs after child")
    require(set(event_times) == {eid for op in truth["operations"] for eid in op["event_ids"]},
            "unowned recon event")
    dns_source = (render_dns(event) for event in rows(root / "recon.jsonl")
                  if event["event_type"] == "dns")
    for expected, actual in zip_longest(dns_source, rows(root / "dns.log")):
        require(expected == actual, "Zeek DNS view diverges from normalized events")

    changes = list(rows(root / "state-changes.jsonl"))
    require(changes and len({c["change_id"] for c in changes}) == len(changes),
            "missing or duplicate state change")
    changes_by_kind = {}
    for change in changes:
        require(valid_asset_id(change["asset_id"]), "state change asset is missing")
        require(all(op["last_observation_at"] < change["effective_at"]
                    for op in truth["operations"]), "state change predates recon")
        key = (change["asset_id"], change["finding_id"])
        kind_changes = changes_by_kind.setdefault(change["finding_type"], {})
        require(key not in kind_changes, "duplicate finding state change")
        kind_changes[key] = change
    for kind in ("vulnerability", "compliance"):
        require(kind in changes_by_kind, f"missing {kind} state change")
        applied = set()
        asset_stream = iter_assets(seed, asset_count)
        asset = next(asset_stream)
        before = rows(root / f"{kind}.jsonl")
        after = rows(root / f"{kind}-followup.jsonl")
        for old, new in zip_longest(before, after):
            require(old is not None and new is not None, "follow-up row count differs")
            key = (old["asset_id"], old["finding_id"])
            require(key == (new["asset_id"], new["finding_id"]),
                    "follow-up finding identity differs")
            while asset["asset_id"] < key[0]:
                asset = next(asset_stream, None)
                require(asset is not None, "finding asset is missing")
            require(asset["asset_id"] == key[0], "finding asset is missing or out of order")
            require(old["host_ip"] == asset["ip"] == new["host_ip"],
                    "finding host address differs")
            change = changes_by_kind[kind].get(key)
            if change:
                require(old[f"{kind}_status"] == change["before"] and
                        new[f"{kind}_status"] == change["after"],
                        "state change does not match assessments")
                require(new["remediation_change_id"] == change["change_id"],
                        "follow-up does not reference its change")
                require(new["assessment_at"] > change["effective_at"],
                        "follow-up assessment predates change")
                if kind == "compliance":
                    require(old["actual_value"] == change["actual_value_before"] and
                            new["actual_value"] == change["actual_value_after"],
                            "control value does not match change")
                applied.add(key)
            else:
                require(old[f"{kind}_status"] == new[f"{kind}_status"],
                        "unplanned finding status change")
        require(applied == set(changes_by_kind[kind]), "state change finding is missing")
    timeline = list(rows(root / "timeline.jsonl"))
    require([item["at"] for item in timeline] == sorted(item["at"] for item in timeline),
            "timeline is out of order")
    require({item["change_id"] for item in timeline if item["kind"] == "state_change"} ==
            {change["change_id"] for change in changes}, "timeline change set differs")
    result = {"assets": asset_count, "recon_events": len(event_times),
            "dns_events": dns_count, "state_changes": len(changes)}
    if (root / "identity-truth.json").exists():
        counts = validate_identity_bundle(root, truth, assets, entities)
        result.update(zip(("identities", "identity_events", "identity_changes"), counts))
        identity_truth = json.loads((root / "identity-truth.json").read_text(encoding="utf-8"))
        require({item["event_id"] for item in timeline if item["kind"] == "identity_interaction"} ==
                {item["event_id"] for item in identity_truth["interactions"]},
                "timeline identity interactions differ")
        require({item["change_id"] for item in timeline if item["kind"] == "identity_change"} ==
                {item["change_id"] for item in identity_truth["state_changes"]},
                "timeline identity changes differ")
    return result


def validate_export(path):
    root = Path(path)
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    truth = json.loads((root / "recon-truth.json").read_text(encoding="utf-8"))
    require(truth["run_id"] == manifest["run_id"], "run IDs differ")
    for name, info in manifest["files"].items():
        digest = hashlib.sha256()
        with (root / name).open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        require(digest.hexdigest() == info["sha256"], f"checksum differs: {name}")
    result = validate_bundle(root, truth)
    require(result == manifest["validation"], "validation summary differs")
    return result


def main():
    parser = argparse.ArgumentParser(description="Validate a linked synthetic story export")
    parser.add_argument("path", help="Directory containing run-manifest.json")
    args = parser.parse_args()
    try:
        print(json.dumps(validate_export(args.path), sort_keys=True))
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
