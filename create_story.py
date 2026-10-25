#!/usr/bin/env python3
"""Export one reproducible synthetic environment and linked dataset bundle."""

import argparse
import hashlib
import json
import os
import random
import shutil
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import create_compliance_table as compliance
import create_recon_events as recon
import create_vuln_table as vuln
from common.assets import DEFAULT_HOST_COUNT, build_hosts
from common.endpoint import VERSION as ENDPOINT_VERSION, generate as generate_endpoint
from common.data_access import VERSION as DATA_ACCESS_VERSION, generate as generate_data_access
from common.export import export_records, parse_times
from common.identity import (VERSION as IDENTITY_VERSION, generate as generate_identity,
                             render_windows_xml)
from common.ingress import VERSION as INGRESS_VERSION, generate as generate_ingress
from common.response import VERSION as RESPONSE_VERSION, generate as generate_response
from common.story_validation import validate_bundle
from common.world import VERSION as WORLD_VERSION, SERVICES, iter_assets, iter_entities, iter_relationships, run_id
from common.zeek_dns import render_dns


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_recipe_text(path):
    content = Path(path).read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def recipe_checksums():
    root = Path(__file__).resolve().parent
    paths = [root / name for name in (
        "create_story.py", "create_vuln_table.py", "create_compliance_table.py",
        "create_recon_events.py", "common/assets.py", "common/export.py", "common/world.py",
        "common/zeek_dns.py", "common/story_validation.py", "common/identity.py",
        "common/endpoint.py", "common/data_access.py", "common/ingress.py",
        "common/response.py")]
    for catalog in ("compliance", "recon", "vulnerability"):
        paths.extend(sorted((root / "catalogs" / catalog).glob("*.json")))
    return {path.relative_to(root).as_posix(): sha256_recipe_text(path) for path in paths}


def validate_recon_truth(truth, seed, host_count):
    """Check references in the current recon manifest against exported world IDs."""
    assets = {a["asset_id"] for a in iter_assets(seed, min(host_count, DEFAULT_HOST_COUNT))}
    entities = {e["entity_id"] for e in iter_entities()}
    for operation in truth["operations"]:
        source = operation["source_ref"]
        if ("asset_id" in source) == ("entity_id" in source):
            raise ValueError("Operation must identify one source asset or entity")
        if source.get("asset_id") not in assets and source.get("entity_id") not in entities:
            raise ValueError("Operation source does not resolve in world catalog")
        event_ids = set(operation["event_ids"])
        if len(event_ids) != len(operation["event_ids"]):
            raise ValueError("Duplicate event ID in operation")
        if operation["last_observation_at"] < operation["start_time"]:
            raise ValueError("Observation predates operation")
        for link in operation["interaction_links"]:
            if link["event_id"] not in event_ids:
                raise ValueError("Interaction link references a missing event")
            for key in ("caused_by", "resolved_by", "retry_of"):
                if key in link and link[key] not in event_ids:
                    raise ValueError(f"Interaction link {key} does not resolve")
            if "target_asset_id" in link and link["target_asset_id"] not in assets:
                raise ValueError("Interaction target does not resolve")


def service_consistent_vulnerabilities(seed, as_of, host_count, skipped):
    """Keep only findings supported by this run's modeled service inventory."""
    assets = iter_assets(seed, host_count)
    asset = next(assets)
    for row in vuln.iter_items(seed, as_of, host_count):
        while asset["fqdn"] != row["host_name"]:
            asset = next(assets)
        if row["network_protocol"] == "local" and row["network_port"] == 0:
            row["asset_id"] = asset["asset_id"]
            yield row
        elif row["network_protocol"] == "tcp" and row["network_port"] in SERVICES[asset["role"]]:
            row["asset_id"] = asset["asset_id"]
            yield row
        else:
            skipped["unsupported_service"] += 1


def linked_compliance(seed, as_of, host_count):
    assets = iter_assets(seed, host_count)
    asset = next(assets)
    for row in compliance.iter_items(seed, as_of, host_count=host_count):
        while asset["fqdn"] != row["host_name"]:
            asset = next(assets)
        row["asset_id"] = asset["asset_id"]
        yield row


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)


def choose_remediation(stage):
    """Choose stable, present baseline findings; keep only two rows in memory."""
    web = None
    fallback_vuln = None
    for row in read_jsonl(stage / "vulnerability.jsonl"):
        if row["vulnerability_status"] not in ("open", "reopened"):
            continue
        if fallback_vuln is None:
            fallback_vuln = row
        if (row["host_name"].startswith("prod-web-02.") and
                row["vulnerability_id"] == "CVE-2014-0160"):
            web = row
            break
    control = None
    fallback_control = None
    for row in read_jsonl(stage / "compliance.jsonl"):
        if row["compliance_status"] != "fail":
            continue
        if fallback_control is None:
            fallback_control = row
        if row["host_name"].startswith("prod-file-01.") and row["control_id"] == "WIN-FIREWALL":
            control = row
            break
    selected = [("vulnerability", web or fallback_vuln),
                ("compliance", control or fallback_control)]
    if any(row is None for _, row in selected):
        raise ValueError("Story requires a vulnerable and a noncompliant baseline finding")
    return selected


def remediation_changes(selected, effective_at):
    for kind, row in selected:
        before = row[f"{kind}_status"]
        after = "fixed" if kind == "vulnerability" else "pass"
        change = {
            "change_id": f"change-{kind}-{row['asset_id']}-{row['finding_id']}",
            "kind": "finding_remediation", "effective_at": effective_at,
            "asset_id": row["asset_id"], "finding_id": row["finding_id"],
            "finding_type": kind, "before": before, "after": after,
            "synthetic": True,
        }
        if kind == "compliance":
            change["actual_value_before"] = row["actual_value"]
            change["actual_value_after"] = row["expected_value"]
        yield change


def followup_rows(stage, kind, changes, seed, assessed_at):
    keyed = {(change["asset_id"], change["finding_id"]): change
             for change in changes if change["finding_type"] == kind}
    for row in read_jsonl(stage / f"{kind}.jsonl"):
        row["assessment_id"] = f"synthetic-{seed}-{assessed_at}"
        row["assessment_at"] = assessed_at
        if kind == "compliance":
            row["last_seen"] = assessed_at
        change = keyed.get((row["asset_id"], row["finding_id"]))
        if change:
            row[f"{kind}_status"] = change["after"]
            if kind == "compliance":
                row["actual_value"] = change["actual_value_after"]
            row["remediation_change_id"] = change["change_id"]
        yield row


def export_story(seed, start, duration_minutes, campaign_count, host_count, output_dir):
    if start.tzinfo is None:
        raise ValueError("--start-time must include a timezone")
    if host_count < DEFAULT_HOST_COUNT:
        raise ValueError(f"Full story runs require at least {DEFAULT_HOST_COUNT} hosts")
    if not 1 <= campaign_count <= 100 or duration_minutes < 4 * campaign_count:
        raise ValueError("Invalid recon campaign count or duration")
    target = Path(output_dir).resolve()
    if target.exists():
        raise ValueError(f"Output directory already exists: {target}")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=parent))
    try:
        assessment_at = iso(start - timedelta(minutes=1))
        start_at = iso(start)
        recipe = recipe_checksums()
        recipe_hash = hashlib.sha256(json.dumps(recipe, sort_keys=True).encode()).hexdigest()
        run_identity = run_id(seed, start_at, host_count, duration_minutes,
                              campaign_count, recipe_hash)
        files = {}

        def save(name, records):
            path = stage / name
            count = export_records(path, records, "jsonl")
            files[name] = {"records": count, "sha256": sha256_file(path)}
            return count

        save("assets.jsonl", iter_assets(seed, host_count))
        save("entities.jsonl", iter_entities())
        save("relationships.jsonl", iter_relationships(seed, host_count))
        skipped_findings = {"unsupported_service": 0}
        save("vulnerability.jsonl", service_consistent_vulnerabilities(
            seed, assessment_at, host_count, skipped_findings))
        save("compliance.jsonl", linked_compliance(seed, assessment_at, host_count))
        events, truth = recon.generate(seed, start, duration_minutes, campaign_count)
        save("recon.jsonl", events)
        validate_recon_truth(truth, seed, host_count)
        dns_events, _ = recon.generate(seed, start, duration_minutes, campaign_count)
        save("dns.log", (render_dns(e) for e in dns_events if e["event_type"] == "dns"))
        ingress_run = generate_ingress(read_jsonl(stage / "recon.jsonl"), truth,
                                       list(iter_assets(seed, DEFAULT_HOST_COUNT)))
        for name, records in (("ingress-firewall.jsonl", ingress_run["firewall"]),
                              ("ingress-zeek-conn.jsonl", ingress_run["conn"]),
                              ("ingress-zeek-http.jsonl", ingress_run["http"]),
                              ("ingress-zeek-ssl.jsonl", ingress_run["ssl"]),
                              ("edge-proxy.jsonl", ingress_run["proxy"])):
            save(name, iter(records))
        identity_run = generate_identity(seed, start, duration_minutes, campaign_count,
                                         {host["short"]: host for host in
                                          build_hosts(random.Random(seed), DEFAULT_HOST_COUNT)})
        for name, records in (("identities.jsonl", identity_run["identities"]),
                              ("access-policies.jsonl", identity_run["policies"]),
                              ("web-auth.jsonl", identity_run["web_events"]),
                              ("windows-security.jsonl", identity_run["windows_events"]),
                              ("identity-state.jsonl", identity_run["truth"]["state_changes"])):
            save(name, iter(records))
        windows_xml_path = stage / "windows-security.xml"
        windows_xml_path.write_text("".join(render_windows_xml(row) + "\n"
                                            for row in identity_run["windows_events"]),
                                    encoding="utf-8", newline="\n")
        files[windows_xml_path.name] = {"records": len(identity_run["windows_events"]),
                                        "sha256": sha256_file(windows_xml_path)}
        endpoint_run = generate_endpoint(seed, start, list(iter_assets(seed, DEFAULT_HOST_COUNT)),
                                         identity_run["truth"], identity_run["windows_events"],
                                         truth, read_jsonl(stage / "recon.jsonl"))
        save("sensor-coverage.jsonl", iter(endpoint_run["coverage"]))
        save("sysmon.jsonl", iter(endpoint_run["records"]))
        sysmon_xml_path = stage / "sysmon.xml"
        sysmon_xml_path.write_text("".join(render_windows_xml(row) + "\n"
                                         for row in endpoint_run["records"]),
                                   encoding="utf-8", newline="\n")
        files[sysmon_xml_path.name] = {"records": len(endpoint_run["records"]),
                                       "sha256": sha256_file(sysmon_xml_path)}
        data_run = generate_data_access(seed, list(iter_assets(seed, DEFAULT_HOST_COUNT)),
                                        list(iter_entities()), identity_run["truth"],
                                        identity_run["windows_events"])
        for name, records in (("data-objects.jsonl", data_run["objects"]),
                              ("windows-file.jsonl", data_run["windows"]),
                              ("zeek-conn.jsonl", data_run["conn"]),
                              ("zeek-http.jsonl", data_run["http"]),
                              ("egress-firewall.jsonl", data_run["firewall"])):
            save(name, iter(records))
        file_xml_path = stage / "windows-file.xml"
        file_xml_path.write_text("".join(render_windows_xml(row) + "\n"
                                         for row in data_run["windows"]),
                                 encoding="utf-8", newline="\n")
        files[file_xml_path.name] = {"records": len(data_run["windows"]),
                                     "sha256": sha256_file(file_xml_path)}

        latest_observation = max(datetime.fromisoformat(
            op["last_observation_at"].replace("Z", "+00:00")) for op in truth["operations"])
        effective_at = iso(latest_observation + timedelta(minutes=1))
        followup_at = iso(latest_observation + timedelta(minutes=2))
        changes = list(remediation_changes(choose_remediation(stage), effective_at))
        save("state-changes.jsonl", iter(changes))
        for kind in ("vulnerability", "compliance"):
            save(f"{kind}-followup.jsonl", followup_rows(stage, kind, changes, seed, followup_at))
        response_run = generate_response(seed, list(read_jsonl(stage / "recon.jsonl")),
                                         list(iter_entities()), identity_run, endpoint_run,
                                         ingress_run, data_run, changes, followup_at)
        for name, records in (("detection-rules.jsonl", response_run["rules"]),
                              ("detection-decisions.jsonl", response_run["decisions"]),
                              ("alerts.jsonl", response_run["alerts"]),
                              ("case-actions.jsonl", response_run["case"]),
                              ("response-firewall.jsonl", response_run["firewall"])):
            save(name, iter(records))

        timeline = [{"kind": "baseline_assessment", "at": assessment_at,
                     "datasets": ["vulnerability.jsonl", "compliance.jsonl"]}]
        timeline.extend({"kind": "operation", "at": op["start_time"],
                         "operation_id": op["operation_id"], "family": op["family"],
                         "source_ref": op["source_ref"]} for op in truth["operations"])
        timeline.extend({"kind": "ingress_interaction", "at": link["at"],
                         "network_event_id": link["network_event_id"]}
                        for link in ingress_run["truth"]["interactions"])
        timeline.extend({"kind": "identity_interaction", "at": interaction["at"],
                         "event_id": interaction["event_id"]}
                        for interaction in identity_run["truth"]["interactions"])
        timeline.extend({"kind": "identity_change", "at": change["effective_at"],
                         "change_id": change["change_id"]}
                        for change in identity_run["truth"]["state_changes"])
        timeline.extend({"kind": "endpoint_interaction", "at": event["at"],
                         "event_id": event["event_id"]}
                        for event in endpoint_run["truth"]["interactions"])
        timeline.extend({"kind": "data_access", "at": event["at"],
                         "event_id": event["event_id"]}
                        for event in data_run["truth"]["accesses"])
        timeline.extend({"kind": "outbound_transfer", "at": event["at"],
                         "transfer_id": event["transfer_id"]}
                        for event in data_run["truth"]["transfers"])
        timeline.extend({"kind": "alert", "at": event["fired_at"],
                         "alert_id": event["alert_id"]} for event in response_run["alerts"])
        timeline.extend({"kind": "case_action", "at": event["time"],
                         "action_id": event["action_id"]} for event in response_run["case"])
        timeline.extend({"kind": "response_firewall", "at": event["time"],
                         "rule": event["rule"]} for event in response_run["firewall"])
        timeline.extend({"kind": "state_change", "at": effective_at,
                         "change_id": change["change_id"], "asset_id": change["asset_id"]}
                        for change in changes)
        timeline.append({"kind": "followup_assessment", "at": followup_at,
                         "datasets": ["vulnerability-followup.jsonl", "compliance-followup.jsonl"]})
        save("timeline.jsonl", iter(sorted(timeline, key=lambda item: (item["at"], item["kind"]))))
        truth["run_id"] = run_identity
        truth_path = stage / "recon-truth.json"
        truth_path.write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8", newline="\n")
        files[truth_path.name] = {"sha256": sha256_file(truth_path)}
        ingress_run["truth"]["run_id"] = run_identity
        ingress_truth_path = stage / "ingress-truth.json"
        ingress_truth_path.write_text(json.dumps(ingress_run["truth"], indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8", newline="\n")
        files[ingress_truth_path.name] = {"sha256": sha256_file(ingress_truth_path)}
        identity_run["truth"]["run_id"] = run_identity
        identity_truth_path = stage / "identity-truth.json"
        identity_truth_path.write_text(json.dumps(identity_run["truth"], indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8", newline="\n")
        files[identity_truth_path.name] = {"sha256": sha256_file(identity_truth_path)}
        endpoint_run["truth"]["run_id"] = run_identity
        endpoint_truth_path = stage / "endpoint-truth.json"
        endpoint_truth_path.write_text(json.dumps(endpoint_run["truth"], indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8", newline="\n")
        files[endpoint_truth_path.name] = {"sha256": sha256_file(endpoint_truth_path)}
        data_run["truth"]["run_id"] = run_identity
        data_truth_path = stage / "data-access-truth.json"
        data_truth_path.write_text(json.dumps(data_run["truth"], indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8", newline="\n")
        files[data_truth_path.name] = {"sha256": sha256_file(data_truth_path)}
        response_run["truth"]["run_id"] = run_identity
        response_truth_path = stage / "response-truth.json"
        response_truth_path.write_text(json.dumps(response_run["truth"], indent=2,
                                                 sort_keys=True) + "\n",
                                       encoding="utf-8", newline="\n")
        files[response_truth_path.name] = {"sha256": sha256_file(response_truth_path)}
        validation = validate_bundle(stage, truth)
        manifest = {
            "schema_version": WORLD_VERSION, "run_id": run_identity,
            "seed": seed, "start_time": start_at, "assessment_time": assessment_at,
            "remediation_time": effective_at, "followup_time": followup_at,
            "duration_minutes": duration_minutes, "campaign_count": campaign_count,
            "host_count": host_count,
            "generator_versions": {"world": WORLD_VERSION, "recon": recon.VERSION,
                                   "identity": IDENTITY_VERSION, "endpoint": ENDPOINT_VERSION,
                                   "data_access": DATA_ACCESS_VERSION,
                                   "ingress": INGRESS_VERSION, "response": RESPONSE_VERSION},
            "recipe_sha256": recipe_hash, "recipe_files": recipe,
            "filtered_vulnerability_findings": skipped_findings,
            "validation": validation,
            "files": files,
            "notes": ["All source formats are synthetic", "Scenario truth is separate from observations",
                      "Recon and identity activity currently use the default 23 hosts",
                      "Windows XML, Sysmon XML, Zeek HTTP/conn, and web authentication CIM mappings are not live validated",
                      "Network byte counts and timing do not prove uploaded content identity"],
        }
        (stage / "run-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n")
        for attempt in range(5):
            try:
                os.replace(stage, target)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.1)
        return manifest
    finally:
        if stage.exists():
            if stage.resolve().parent != parent.resolve():
                raise RuntimeError("Refusing to clean up outside the output parent")
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--start-time", required=True, help="ISO 8601 timestamp with timezone")
    parser.add_argument("--duration-minutes", type=int, default=60)
    parser.add_argument("--campaign-count", type=int, default=1)
    parser.add_argument("--host-count", type=int, default=DEFAULT_HOST_COUNT)
    parser.add_argument("--output-dir", required=True, help="New directory for this run")
    parser.add_argument("--cim-output-dir", help="Optional new directory for CIM-shaped observation files")
    args = parser.parse_args()
    try:
        start = datetime.fromisoformat(parse_times([args.start_time])[0].replace("Z", "+00:00"))
        manifest = export_story(args.seed, start, args.duration_minutes,
                                args.campaign_count, args.host_count, args.output_dir)
        if args.cim_output_dir:
            from create_cim_events import export_cim
            cim_manifest = export_cim(args.output_dir, args.cim_output_dir)
            print(f"Wrote {cim_manifest['cim_records']} CIM-shaped observations to "
                  f"{Path(args.cim_output_dir).resolve()}")
        print(f"Wrote {manifest['run_id']} to {Path(args.output_dir).resolve()}")
        print("Records:", {name: item["records"] for name, item in manifest["files"].items()
                           if "records" in item})
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
