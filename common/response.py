"""Deterministic detections, case actions, and effective containment."""

import hashlib
from datetime import datetime, timedelta, timezone


VERSION = "1.0"
RULES = (
    {"rule_id": "recon-port-burst", "version": "1.0", "signal": "network probe burst",
     "source": "recon.jsonl", "threshold": 3, "collection_lag_seconds": 0,
     "suppression": "authorized scanner entity in inventory"},
    {"rule_id": "sensitive-read-outbound", "version": "1.0",
     "signal": "confidential read followed by outbound POST",
     "sources": ["data-objects.jsonl", "windows-security.jsonl", "windows-file.jsonl",
                 "zeek-http.jsonl", "entities.jsonl"],
     "file_collection_lag_seconds": 2, "network_collection_lag_seconds": 1,
     "suppression": "none; requires matching session, source, time, and byte size"},
)


def parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stable_id(seed, label):
    return hashlib.sha256(f"{VERSION}:{seed}:{label}".encode()).hexdigest()[:16]


def generate(seed, recon_events, entities, identity_run, endpoint_run,
             ingress_run, data_run, changes, followup_at):
    """Create alerts from available observations, then test a containment effect."""
    decisions, alerts = [], []
    for entity in entities:
        if entity["role"] not in ("scanner", "approved_scanner"):
            continue
        probes = [row for row in recon_events if row["event_type"] == "network_connection" and
                  row["src_ip"] == entity["ip"]][:3]
        if len(probes) < 3:
            continue
        candidate_at = max(parse(row["collected_at"]) for row in probes)
        evidence = [{"source": "recon", "event_id": row["event_id"],
                     "observed_at": row["timestamp"], "available_at": row["collected_at"]}
                    for row in probes]
        decision = {"decision_id": "decision-" + stable_id(seed, entity["entity_id"]),
                    "rule_id": "recon-port-burst", "rule_version": "1.0",
                    "evaluated_at": stamp(candidate_at),
                    "source_ip": probes[0]["src_ip"],
                    "outcome": "suppressed" if entity["authorized"] else "alert",
                    "reason": "approved-scanner-inventory" if entity["authorized"] else "threshold-met",
                    "evidence": evidence}
        decisions.append(decision)
        if not entity["authorized"]:
            alerts.append({"alert_id": "alert-" + stable_id(seed, "scan"),
                           "rule_id": decision["rule_id"], "rule_version": "1.0",
                           "fired_at": decision["evaluated_at"],
                           "first_observed_at": min(row["timestamp"] for row in probes),
                           "last_observed_at": max(row["timestamp"] for row in probes),
                           "detection_latency_ms": int((candidate_at - max(
                               parse(row["timestamp"]) for row in probes)).total_seconds() * 1000),
                           "severity": "medium", "title": "Network probe burst",
                           "evidence": evidence})

    confidential = {row["path"]: row for row in data_run["objects"]
                    if row["classification"] == "confidential"}
    logons = {row["TargetLogonId"]: row for row in identity_run["windows_events"]
              if row["EventCode"] == 4624 and "IpAddress" in row}
    external = {row["ip"]: row for row in entities if not row["authorized"]}
    candidates = []
    for file_row in data_run["windows"]:
        if file_row["EventCode"] != 4663 or file_row["ObjectName"] not in confidential:
            continue
        logon = logons.get(file_row["SubjectLogonId"])
        if logon is None or logon["TargetUserName"] != file_row["SubjectUserName"]:
            continue
        file_at = parse(file_row["TimeCreated"])
        for net_row in data_run["http"]:
            network_at = datetime.fromtimestamp(net_row["ts"], timezone.utc)
            if (net_row["method"] == "POST" and
                    net_row["id.orig_h"] == logon["IpAddress"] and
                    net_row["id.resp_h"] in external and
                    net_row["request_body_len"] == confidential[file_row["ObjectName"]]["size_bytes"] and
                    timedelta(0) < network_at - file_at <= timedelta(minutes=1)):
                candidates.append((file_row, net_row))
    if len(candidates) != 1:
        raise ValueError("Expected one source-observable confidential read and outbound POST")
    file_event, network = candidates[0]
    network_at = datetime.fromtimestamp(network["ts"], timezone.utc)
    network_at = datetime.fromtimestamp(network["ts"], timezone.utc)
    file_available = parse(file_event["TimeCreated"]) + timedelta(seconds=2)
    network_available = network_at + timedelta(seconds=1)
    fired = max(file_available, network_available)
    evidence = [
        {"source": "windows-file", "computer": file_event["Computer"],
         "record_id": file_event["EventRecordID"],
         "observed_at": file_event["TimeCreated"], "available_at": stamp(file_available)},
        {"source": "zeek-http", "uid": network["uid"],
         "observed_at": stamp(network_at), "available_at": stamp(network_available)},
    ]
    transfer_alert = {"alert_id": "alert-" + stable_id(seed, "read-outbound"),
                      "rule_id": "sensitive-read-outbound", "rule_version": "1.0",
                      "fired_at": stamp(fired), "first_observed_at": file_event["TimeCreated"],
                      "last_observed_at": stamp(network_at),
                      "detection_latency_ms": int((fired - network_at).total_seconds() * 1000),
                      "severity": "high", "title": "Sensitive read followed by outbound POST",
                      "evidence": evidence}
    alerts.append(transfer_alert)
    decisions.append({"decision_id": "decision-" + stable_id(seed, "read-outbound"),
                      "rule_id": transfer_alert["rule_id"], "rule_version": "1.0",
                      "evaluated_at": transfer_alert["fired_at"], "outcome": "alert",
                      "reason": "read-and-post-correlation", "evidence": evidence})
    alerts.sort(key=lambda row: (row["fired_at"], row["alert_id"]))
    decisions.sort(key=lambda row: (row["evaluated_at"], row["decision_id"]))

    # The answer key is consulted only after the alert has been derived from source data.
    upload = next(row for row in data_run["truth"]["transfers"]
                  if row["uid"] == network["uid"])

    case_id = "case-" + stable_id(seed, "operator-egress")
    action_base = fired + timedelta(seconds=1)
    case = []

    def action(kind, when, **fields):
        case.append({"action_id": "case-action-" + stable_id(seed, kind),
                     "case_id": case_id, "time": stamp(when), "action": kind,
                     "trigger_alert_id": transfer_alert["alert_id"], **fields})

    action("opened", action_base, status="investigating")
    action("hypothesis", action_base + timedelta(seconds=1),
           statement="Sensitive read may be related to outbound POST; file content not observed",
           status="investigating")
    config = next(row for row in endpoint_run["records"] if row["EventCode"] == 13)
    web_probe = next(row for row in ingress_run["proxy"] if row["uri"] == "/.env")
    public_probe = next(row for row in ingress_run["truth"]["interactions"]
                        if row["application_event_id"] and row["public_destination"] and
                        row["zeek_uid"] in {item["uid"] for item in ingress_run["http"]})
    auth_failure = next(row for row in identity_run["web_events"]
                        if row["event"] == "login" and row["outcome"] == "failure")
    operator_logon = next(row for row in identity_run["windows_events"]
                          if row["EventCode"] == 4624 and row.get("TargetUserName") == "operator")
    action("reviewed", action_base + timedelta(seconds=2), status="reviewed",
           conclusion="confirmed outbound policy violation; uploaded content unverified",
           context=[{"source": "relationships", "relationship_id":
                     f"{public_probe['target_asset_id']}-public-tcp-80"},
                    {"source": "edge-proxy", "time": web_probe["time"], "uri": web_probe["uri"]},
                    {"source": "web-auth", "request_id": auth_failure["request_id"]},
                    {"source": "windows-security", "record_id": operator_logon["EventRecordID"]},
                    {"source": "sysmon", "record_id": config["EventRecordID"]}],
           context_note="Public probe and failed login share an IP; actor continuity is unproven")
    containment_at = action_base + timedelta(seconds=3)
    action("contained", containment_at, status="contained",
           target_ip=network["id.resp_h"],
           control="block-bastion-to-upload-endpoint")
    retry_at = containment_at + timedelta(seconds=1)
    original_fw = next(row for row in data_run["firewall"]
                       if row["src_ip"] == network["id.orig_h"] and
                       row["dest_ip"] == network["id.resp_h"] and
                       row["action"] == "allow")
    retry = {"time": stamp(retry_at), "device": original_fw["device"],
             "action": "block", "src_ip": original_fw["src_ip"],
             "src_port": original_fw["src_port"] + 100, "dest_ip": original_fw["dest_ip"],
             "dest_port": original_fw["dest_port"], "protocol": "tcp",
             "bytes_out": 0, "bytes_in": 0, "rule": "block-bastion-to-upload-endpoint"}
    for change in changes:
        action("remediation-" + change["finding_type"], parse(change["effective_at"]),
               status="remediating", change_id=change["change_id"],
               finding_id=change["finding_id"])
    action("verified", parse(followup_at) + timedelta(seconds=1), status="closed",
           conclusion="containment held; modeled findings passed follow-up assessment")
    case.sort(key=lambda row: (row["time"], row["action_id"]))
    return {"rules": list(RULES), "decisions": decisions, "alerts": alerts,
            "case": case, "firewall": [retry],
            "truth": {"schema_version": VERSION, "case_id": case_id,
                      "containment_effective_at": stamp(containment_at),
                      "blocked_retry_at": retry["time"],
                      "blocked_retry_destination_entity_id": upload["destination_entity_id"],
                      "trigger_transfer_id": upload["transfer_id"],
                      "suppressed_control_entity_id": "entity-approved-scanner-01",
                      "expected_outcome": "blocked retry; report content identity not sensor-proven"}}
