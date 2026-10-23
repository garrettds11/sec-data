"""Validate the cross-file contract of a linked synthetic story bundle."""

import argparse
import hashlib
import json
from itertools import zip_longest
from pathlib import Path

from common.zeek_dns import render_dns
from common.identity import render_windows_xml
from common.data_access import OBJECTS
from common.world import ENTITY_IPS, iter_assets, iter_entities, iter_relationships


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


def validate_endpoint_bundle(root, truth, assets):
    endpoint_truth = json.loads((root / "endpoint-truth.json").read_text(encoding="utf-8"))
    identity_truth = json.loads((root / "identity-truth.json").read_text(encoding="utf-8"))
    require(endpoint_truth["run_id"] == truth["run_id"], "endpoint run ID differs")
    monitored = endpoint_truth["monitored_asset_id"]
    require(monitored in assets and assets[monitored]["family"] == "windows",
            "monitored endpoint is missing or non-Windows")
    coverage = list(rows(root / "sensor-coverage.jsonl"))
    require({row["asset_id"] for row in coverage} == set(assets),
            "sensor coverage does not describe the fixture assets")
    enabled = [row for row in coverage if row["enabled"]]
    require(len(enabled) == 1 and enabled[0]["asset_id"] == monitored and
            set(enabled[0]["event_codes"]) == {1, 3, 5, 11, 13},
            "Sysmon coverage differs from modeled source")
    require(all(not row["event_codes"] for row in coverage if not row["enabled"]),
            "unmonitored host lists Sysmon events")

    events = {}
    for row in rows(root / "sysmon.jsonl"):
        eid = f"sysmon-{row['Computer'].split('.')[0]}-{row['EventRecordID']}"
        require(eid not in events, "duplicate Sysmon record ID")
        require(row["Computer"] == assets[monitored]["fqdn"] and
                row["EventCode"] in enabled[0]["event_codes"] and
                row["Provider"] == "Microsoft-Windows-Sysmon" and
                row["Channel"] == "Microsoft-Windows-Sysmon/Operational",
                "Sysmon event is outside sensor coverage")
        events[eid] = row
    with (root / "sysmon.xml").open(encoding="utf-8") as handle:
        for expected, actual in zip_longest((render_windows_xml(row) for row in events.values()),
                                             (line.rstrip("\r\n") for line in handle)):
            require(expected == actual, "Sysmon XML view diverges from JSON projection")
    links = {row["event_id"]: row for row in endpoint_truth["interactions"]}
    require(len(links) == len(events) and set(links) == set(events),
            "Sysmon interaction set differs from source")
    sessions = {row["session_id"]: row for row in identity_truth["sessions"]}
    identities = {row["identity_id"]: row for row in rows(root / "identities.jsonl")}
    windows_logons = {row["TargetUserName"]: row for row in rows(root / "windows-security.jsonl")
                      if row["EventCode"] == 4624 and row["Computer"] == assets[monitored]["fqdn"]}
    recon = {row["event_id"]: row for row in rows(root / "recon.jsonl")}
    operation = next((op for op in truth["operations"] if
                      op["operation_id"] == endpoint_truth["related_recon_operation_id"]), None)
    require(operation is not None and operation["family"] == "internal",
            "endpoint recon operation is missing")
    processes = {}
    terminations = {}
    for eid, row in events.items():
        link = links[eid]
        require(link["at"] == row["TimeCreated"] and
                link["event_code"] == row["EventCode"] and
                link["asset_id"] == monitored and
                link["session_id"] in sessions and
                link["identity_id"] == sessions[link["session_id"]]["identity_id"] and
                sessions[link["session_id"]]["asset_id"] == monitored and
                sessions[link["session_id"]]["started_at"] <= link["at"],
                "Sysmon event does not resolve to an active session")
        account = identities[link["identity_id"]]["account"]
        require(row["User"] == account, "Sysmon user differs from session")
        if row["EventCode"] == 1:
            pguid = row["ProcessGuid"]
            require(pguid not in processes and link["process_guid"] == pguid,
                    "duplicate or mismatched process GUID")
            require(row["LogonId"] == windows_logons[account.split("\\")[1]]["TargetLogonId"],
                    "Sysmon logon ID differs from Security logon")
            processes[pguid] = row
        elif row["EventCode"] == 5:
            require(row["ProcessGuid"] not in terminations,
                    "duplicate process termination")
            terminations[row["ProcessGuid"]] = row["TimeCreated"]
        if "related_recon_event_id" in link:
            related = recon.get(link["related_recon_event_id"])
            require(related is not None and related["event_id"] in operation["event_ids"] and
                    related["timestamp"] == row["TimeCreated"],
                    "Sysmon/recon correlation differs")
            if row["EventCode"] == 3:
                require(related["event_type"] == "network_connection" and
                        row["SourceIp"] == related["src_ip"] and
                        row["DestinationIp"] == related["dst_ip"] and
                        row["DestinationPort"] == related["dst_port"],
                        "Sysmon network observation differs from recon")
            elif row["EventCode"] == 1:
                require(related["event_type"] == "process" and
                        row["Image"].split("\\")[-1] == related["executable"],
                        "Sysmon process differs from recon")
            else:
                raise ValueError("Invalid story bundle: invalid Sysmon/recon link")
    for row in events.values():
        pguid = row["ProcessGuid"]
        require(pguid in processes and processes[pguid]["TimeCreated"] <= row["TimeCreated"],
                "Sysmon event references a missing or later process")
        if pguid in terminations:
            require(row["TimeCreated"] <= terminations[pguid],
                    "Sysmon activity follows process termination")
        if row["EventCode"] == 1 and "ParentProcessGuid" in row:
            parent = processes.get(row["ParentProcessGuid"])
            require(parent is not None and parent["TimeCreated"] < row["TimeCreated"] and
                    parent["ProcessId"] == row["ParentProcessId"] and
                    parent["Image"] == row["ParentImage"],
                    "Sysmon parent process differs")
    require(any(row["EventCode"] == 11 and row["User"] == "LAB\\analyst" for row in events.values()) and
            any(row["EventCode"] == 13 and row["User"] == "LAB\\operator" for row in events.values()) and
            any(row["EventCode"] == 11 and row["User"] == "LAB\\svc_backup" for row in events.values()),
            "endpoint activity or benign control is missing")
    grant = next(row for row in identity_truth["state_changes"] if row["kind"] == "group_membership")
    require(all(row["TimeCreated"] > grant["effective_at"] for row in events.values()
                if row["EventCode"] == 13), "registry change predates privilege grant")
    return len(events), len(processes)


def validate_data_access_bundle(root, truth, assets, entities):
    data_truth = json.loads((root / "data-access-truth.json").read_text(encoding="utf-8"))
    identity_truth = json.loads((root / "identity-truth.json").read_text(encoding="utf-8"))
    endpoint_truth = json.loads((root / "endpoint-truth.json").read_text(encoding="utf-8"))
    require(data_truth["run_id"] == truth["run_id"], "data access run ID differs")
    objects = {row["object_id"]: row for row in rows(root / "data-objects.jsonl")}
    require(len(objects) == len(OBJECTS) and
            all({key: value for key, value in row.items() if key not in ("asset_id", "synthetic")} ==
                expected and row["asset_id"] in assets and row["synthetic"]
                for row, expected in zip(objects.values(), OBJECTS)),
            "data object catalog differs")
    windows = {}
    for row in rows(root / "windows-file.jsonl"):
        eid = f"windows-{row['Computer'].split('.')[0]}-{row['EventRecordID']}"
        require(eid not in windows, "duplicate file audit event")
        windows[eid] = row
    with (root / "windows-file.xml").open(encoding="utf-8") as handle:
        for expected, actual in zip_longest((render_windows_xml(row) for row in windows.values()),
                                             (line.rstrip("\r\n") for line in handle)):
            require(expected == actual, "file audit XML differs")
    accesses = {row["event_id"]: row for row in data_truth["accesses"]}
    sessions = {row["session_id"]: row for row in identity_truth["sessions"]}
    identities = {row["identity_id"]: row for row in rows(root / "identities.jsonl")}
    logons = {(row["Computer"], row["TargetUserName"]): row for row in
              rows(root / "windows-security.jsonl") if row["EventCode"] == 4624}
    require(set(windows) == set(accesses), "file audit interactions differ")
    for eid, link in accesses.items():
        row = windows[eid]
        obj = objects[link["object_id"]]
        session = sessions[link["session_id"]]
        account = identities[link["identity_id"]]["account"].split("\\")[1]
        require(link["asset_id"] == obj["asset_id"] == session["asset_id"] and
                link["identity_id"] == session["identity_id"] and
                link["at"] == row["TimeCreated"] and session["started_at"] < link["at"] and
                row["Computer"] == assets[obj["asset_id"]]["fqdn"] and
                row["SubjectUserName"] == account and
                row["SubjectLogonId"] == logons[(row["Computer"], account)]["TargetLogonId"] and
                row["AccessMask"] == "0x1", "file audit/session reference differs")
        if link["result"] == "success":
            require(row["EventCode"] == 4663 and row["ObjectName"] == obj["path"] and
                    row["Keywords"] == "0x8020000000000000",
                    "successful file read differs")
        else:
            require(link["result"] == "denied" and row["EventCode"] == 5145 and
                    row["Keywords"] == "0x8010000000000000" and
                    row["IpAddress"] == assets[link["source_asset_id"]]["ip"] and
                    row["ShareLocalPath"] + "\\" + row["RelativeTargetName"] == obj["path"],
                    "denied share audit differs")
    conn = {row["uid"]: row for row in rows(root / "zeek-conn.jsonl")}
    http = {row["uid"]: row for row in rows(root / "zeek-http.jsonl")}
    firewall = list(rows(root / "egress-firewall.jsonl"))
    transfers = {row["transfer_id"]: row for row in data_truth["transfers"]}
    require(len(transfers) == 4 and len(firewall) == len(transfers) and
            set(conn) == set(http) and len(conn) == 3,
            "outbound observation count differs")
    used_indices = set()
    for link in transfers.values():
        index = link["firewall_index"]
        require(index not in used_indices and 0 <= index < len(firewall),
                "firewall reference duplicates or is missing")
        used_indices.add(index)
        fw = firewall[index]
        source = assets[link["source_asset_id"]]
        entity = entities[link["destination_entity_id"]]
        session = sessions[link["session_id"]]
        require(link["identity_id"] == session["identity_id"] and
                session["started_at"] <= link["at"] and
                fw["time"] == link["at"] and fw["src_ip"] == source["ip"] and
                fw["dest_ip"] == entity["ip"] and fw["action"] == link["result"],
                "egress endpoint or session differs")
        read_id = link["related_read_event_id"]
        if read_id:
            read = accesses[read_id]
            require(read["result"] == "success" and read["identity_id"] == link["identity_id"] and
                    read["session_id"] == link["session_id"] and read["at"] < link["at"] and
                    objects[read["object_id"]]["size_bytes"] == link["body_bytes"],
                    "transfer is not backed by a successful matching read")
        if link["result"] == "allow":
            uid = link["uid"]
            require(uid in conn and uid in http and
                    conn[uid]["id.orig_h"] == http[uid]["id.orig_h"] == source["ip"] and
                    conn[uid]["id.resp_h"] == http[uid]["id.resp_h"] == entity["ip"] and
                    conn[uid]["id.orig_p"] == http[uid]["id.orig_p"] == fw["src_port"] and
                    http[uid]["method"] == link["method"] and
                    http[uid]["request_body_len"] == link["body_bytes"] and
                    conn[uid]["orig_ip_bytes"] == fw["bytes_out"] >= link["body_bytes"] and
                    conn[uid]["resp_ip_bytes"] == fw["bytes_in"] and
                    abs((http[uid]["ts"] - conn[uid]["ts"]) - 0.05) < 0.001,
                    "Zeek, firewall, and transfer bytes differ")
        else:
            require(link["result"] == "block" and link["uid"] is None and
                    link["body_bytes"] == fw["bytes_out"] == fw["bytes_in"] == 0 and
                    read_id is None, "blocked transfer claims a payload")
    require({row["result"] for row in transfers.values()} == {"allow", "block"} and
            any(row["method"] == "GET" and row["body_bytes"] == 0 for row in transfers.values()) and
            any(row["transfer_id"] == "transfer-backup" and row["related_read_event_id"]
                for row in transfers.values()), "egress controls are missing")
    backup = transfers["transfer-backup"]
    sysmon = {f"sysmon-{row['Computer'].split('.')[0]}-{row['EventRecordID']}": row
              for row in rows(root / "sysmon.jsonl")}
    endpoint_link = next((row for row in endpoint_truth["interactions"]
                          if row.get("related_transfer_id") == backup["transfer_id"]), None)
    require(endpoint_link is not None and endpoint_link["event_id"] in sysmon and
            sysmon[endpoint_link["event_id"]]["DestinationIp"] ==
            entities[backup["destination_entity_id"]]["ip"] and
            sysmon[endpoint_link["event_id"]]["SourceIp"] ==
            assets[backup["source_asset_id"]]["ip"],
            "backup endpoint network link differs")
    return len(windows), len(conn), len(firewall)


def validate_ingress_bundle(root, truth, assets, entities):
    ingress = json.loads((root / "ingress-truth.json").read_text(encoding="utf-8"))
    require(ingress["run_id"] == truth["run_id"], "ingress run ID differs")
    recon = {row["event_id"]: row for row in rows(root / "recon.jsonl")}
    firewall = list(rows(root / "ingress-firewall.jsonl"))
    conn = {row["uid"]: row for row in rows(root / "ingress-zeek-conn.jsonl")}
    http = {row["uid"]: row for row in rows(root / "ingress-zeek-http.jsonl")}
    ssl = {row["uid"]: row for row in rows(root / "ingress-zeek-ssl.jsonl")}
    proxy = list(rows(root / "edge-proxy.jsonl"))
    links = ingress["interactions"]
    require(len(links) == len(firewall) == 4 and len(conn) == len(proxy) == 3 and
            len(http) == 2 and len(ssl) == 1 and
            len({row["network_event_id"] for row in links}) == 4,
            "ingress sensor coverage or event IDs differ")
    used_firewall, used_proxy = set(), set()
    for link in links:
        network = recon[link["network_event_id"]]
        fi = link["firewall_index"]
        require(fi not in used_firewall and 0 <= fi < len(firewall),
                "ingress firewall reference differs")
        used_firewall.add(fi)
        fw = firewall[fi]
        target = assets[link["target_asset_id"]]
        require(network["event_type"] == "network_connection" and
                network["timestamp"] == fw["time"] == link["at"] and
                network["collected_at"] == fw["collected_at"] and
                fw["time"] <= fw["collected_at"] and
                network["src_ip"] == fw["src_ip"] == link["source_ip"] and
                network["dst_ip"] == fw["dest_ip"] and
                network["dst_port"] == fw["dest_port"] and
                target["ip"] == (link["translated_destination"] or target["ip"]),
                "ingress firewall/recon address or time differs")
        if link["public_destination"]:
            require(target["externally_exposed"] and
                    link["public_destination"] == network["dst_ip"] and
                    network["sensor_id"] == "perimeter-fw-01",
                    "ingress public exposure differs")
        else:
            require(network["dst_ip"] == target["ip"], "internal destination differs")
        app_id = link["application_event_id"]
        uid = link["zeek_uid"]
        if app_id is None:
            require(network["outcome"] == "blocked" and fw["action"] == "block" and
                    fw["bytes_in"] == 0 and uid is None and
                    link["translated_destination"] is None and "proxy_index" not in link,
                    "blocked ingress has downstream evidence")
            continue
        app = recon[app_id]
        require(network["outcome"] == "connected" and fw["action"] == "allow" and
                fw["translated_dest_ip"] == target["ip"] == app["dst_ip"] and
                app["timestamp"] > network["timestamp"] and
                app["collected_at"] >= app["timestamp"] and
                app["src_ip"] == network["src_ip"] and
                app["dst_port"] == network["dst_port"] and
                any(item["event_id"] == app_id and item.get("caused_by") == link["network_event_id"]
                    for op in truth["operations"] for item in op["interaction_links"]),
                "ingress application causality differs")
        pi = link["proxy_index"]
        require(pi not in used_proxy and 0 <= pi < len(proxy), "edge proxy reference differs")
        used_proxy.add(pi)
        edge = proxy[pi]
        require(edge["time"] == app["timestamp"] and edge["collected_at"] == app["collected_at"] and
                edge["client_ip"] == app["src_ip"] and edge["server_ip"] == app["dst_ip"] and
                edge["uri"] == app["uri"] and edge["method"] == app["method"] and
                edge["status"] == app["status"] and
                edge["response_bytes"] == app["response_bytes"],
                "edge proxy/application request differs")
        require(uid in conn and conn[uid]["id.orig_h"] == fw["src_ip"] and
                conn[uid]["id.orig_p"] == fw["src_port"] and
                conn[uid]["id.resp_h"] == target["ip"] and
                conn[uid]["id.resp_p"] == fw["dest_port"] and
                conn[uid]["orig_ip_bytes"] == fw["bytes_out"] and
                conn[uid]["resp_ip_bytes"] == fw["bytes_in"] >= app["response_bytes"],
                "ingress flow/edge byte or address differs")
        if network["dst_port"] == 443:
            require(uid in ssl and uid not in http and ssl[uid]["server_name"] == app["host"] and
                    ssl[uid]["established"] and "uri" not in ssl[uid],
                    "TLS visibility differs")
        else:
            require(uid in http and uid not in ssl and http[uid]["uri"] == app["uri"] and
                    http[uid]["status_code"] == app["status"] and
                    http[uid]["response_body_len"] == app["response_bytes"],
                    "cleartext HTTP observation differs")
    require({link["zeek_uid"] for link in links if link["zeek_uid"]} == set(conn) and
            any(recon[link["application_event_id"]]["uri"] == "/.env" for link in links
                if link["application_event_id"]) and
            any(recon[link["application_event_id"]]["uri"] == "/" and
                link["source_ip"] != ENTITY_IPS["entity-external-scanner-01"] for link in links
                if link["application_event_id"]),
            "ingress suspicious or benign controls differ")
    return len(firewall), len(conn), len(ssl)


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
    if (root / "endpoint-truth.json").exists():
        counts = validate_endpoint_bundle(root, truth, assets)
        result.update(zip(("endpoint_events", "endpoint_processes"), counts))
        endpoint_truth = json.loads((root / "endpoint-truth.json").read_text(encoding="utf-8"))
        require({item["event_id"] for item in timeline if item["kind"] == "endpoint_interaction"} ==
                {item["event_id"] for item in endpoint_truth["interactions"]},
                "timeline endpoint interactions differ")
    if (root / "data-access-truth.json").exists():
        counts = validate_data_access_bundle(root, truth, assets, entities)
        result.update(zip(("file_audit_events", "zeek_connections", "firewall_events"), counts))
        data_truth = json.loads((root / "data-access-truth.json").read_text(encoding="utf-8"))
        require({item["event_id"] for item in timeline if item["kind"] == "data_access"} ==
                {item["event_id"] for item in data_truth["accesses"]} and
                {item["transfer_id"] for item in timeline if item["kind"] == "outbound_transfer"} ==
                {item["transfer_id"] for item in data_truth["transfers"]},
                "timeline data access or transfer differs")
    if (root / "ingress-truth.json").exists():
        counts = validate_ingress_bundle(root, truth, assets, entities)
        result.update(zip(("ingress_firewall_events", "ingress_flows", "ingress_tls"), counts))
        ingress_truth = json.loads((root / "ingress-truth.json").read_text(encoding="utf-8"))
        require({item["network_event_id"] for item in timeline if item["kind"] == "ingress_interaction"} ==
                {item["network_event_id"] for item in ingress_truth["interactions"]},
                "timeline ingress interactions differ")
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
