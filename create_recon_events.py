#!/usr/bin/env python3
"""Generate offline, normalized synthetic discovery telemetry and a separate answer key."""
import argparse
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common.assets import build_hosts
from common.export import export_records, parse_times
from common.world import ENTITY_IPS, PUBLIC_IPS, SERVICES, asset_id
from common.zeek_dns import render_dns

VERSION = "1.1"
FAMILIES = ("external", "internal", "nmap", "approved")
EVIDENCE = {
    "external": ["androxgh0st", "nmap-phases"],
    "internal": ["bianlian"],
    "nmap": ["nmap-phases", "nmap-discovery"],
    "approved": ["nmap-phases"],
}
TECHNIQUES = {
    "external": ["T1595"], "internal": ["T1046", "T1135"],
    "nmap": ["T1046"], "approved": [],
}


def stamp(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def event_id(seed, operation_start, sequence, kind, sensor, fields):
    identity = json.dumps([VERSION, seed, stamp(operation_start), sequence, kind, sensor, fields],
                          sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()[:24]


class Operation:
    def __init__(self, seed, number, family, start, assets, endpoint=True, http=True,
                 nmap_indicator="explicit", background_offsets=(51,), nmap_profile=None):
        self.seed, self.number, self.family, self.start = seed, number, family, start
        self.assets = assets
        self.endpoint, self.http, self.nmap_indicator = endpoint, http, nmap_indicator
        self.background_offsets = background_offsets
        self.nmap_profile = nmap_profile
        self.rng = random.Random(f"recon:{VERSION}:{seed}:{number}:{family}")
        self.events = []
        self.links = []
        self.omitted = Counter()
        self.dns_cache = {}
        self.dns_ports = set()

    def emit(self, kind, seconds, sensor, **fields):
        when = self.start + timedelta(seconds=seconds)
        sequence = f"{self.number}:{len(self.events)}"
        record = {
            "schema_version": VERSION,
            "event_id": event_id(self.seed, self.start, sequence, kind, sensor, fields),
            "timestamp": stamp(when),
            "collected_at": stamp(when + timedelta(milliseconds=self.rng.randint(5, 300))),
            "sensor_id": sensor, "event_type": kind, "synthetic": True,
        }
        record.update(fields)
        self.events.append(record)
        return record["event_id"]

    def process(self, seconds, host, executable):
        if not self.endpoint:
            self.omitted["unmonitored_endpoint"] += 1
            return
        self.emit("process", seconds, "endpoint-lab-01", host_name=host["fqdn"],
                  host_ip=host["ip"], executable=executable, user="LAB\\analyst",
                  process_id=1000 + self.number)

    def dns(self, seconds, host, name, query_type="A", rcode="NOERROR",
            answers=(), ttls=()):
        if len(answers) != len(ttls):
            raise ValueError("DNS answers and TTLs must have the same length")
        if rcode != "NOERROR" and answers:
            raise ValueError("Unsuccessful DNS queries cannot have answers")
        # DNS details have a separate stream so adding queries does not alter
        # connection timing or other sensor observations.
        rng = random.Random(f"dns:{VERSION}:{self.seed}:{self.number}:{seconds}:{name}:{query_type}")
        if len(self.dns_ports) == 16384:
            raise ValueError("DNS client port space exhausted for one operation")
        client_port = rng.randint(49152, 65535)
        while client_port in self.dns_ports:
            client_port = 49152 + (client_port - 49151) % 16384
        self.dns_ports.add(client_port)
        response_observed = rcode is not None
        fields = dict(client_ip=host["ip"], client_port=client_port,
                      resolver_ip=ENTITY_IPS["entity-enterprise-resolver-01"],
                      resolver_port=53, transport="udp",
                      transaction_id=rng.randint(0, 65535), query=name,
                      query_type=query_type, query_class="IN", rcode=rcode,
                      answers=list(answers), answer_ttls=list(ttls),
                      response_observed=response_observed)
        if response_observed:
            fields["response_time_ms"] = rng.randint(2, 80)
        return self.emit("dns", seconds, "enterprise-resolver-01", **fields)

    def connection(self, seconds, src_ip, host, port, public=False, probe="connect"):
        dst_ip = PUBLIC_IPS[host["short"]] if public else host["ip"]
        if public and port not in (80, 443):
            outcome = "blocked"
        elif port not in SERVICES[host["role"]]:
            outcome = "rejected"
        elif not public and src_ip.startswith("10.30.") and host["env"] == "prod" and port == 3389:
            outcome = "blocked"
        else:
            outcome = "answered" if probe == "syn" else "connected"
        if outcome == "blocked":
            packets, bytes_out, bytes_in = 1, 60, 0
        elif outcome == "rejected":
            packets, bytes_out, bytes_in = 2, 60, 40
        elif probe == "syn":
            packets, bytes_out, bytes_in = 2, 60, 60
        else:
            packets, bytes_out, bytes_in = 5, 160, 120
        eid = self.emit("network_connection", seconds, "perimeter-fw-01" if public else "eastwest-fw-01",
                        src_ip=src_ip, dst_ip=dst_ip, dst_port=port, transport="tcp",
                        probe_type=probe, outcome=outcome, packets=packets,
                        bytes_out=bytes_out, bytes_in=bytes_in,
                        duration_ms=self.rng.randint(3, 80) if outcome != "blocked" else 0)
        self.links.append({"event_id": eid, "target_asset": host["fqdn"],
                           "target_asset_id": asset_id(host),
                           "translated_destination": host["ip"] if public else None})
        return outcome, eid

    def web(self, seconds, src_ip, host, port, uri, status=404, public=False,
            user_agent=None, caused_by=None):
        if not self.http:
            self.omitted["http_sensor_disabled"] += 1
            return
        if port not in (80, 443):
            raise ValueError("HTTP requires a modeled web service")
        # Application sensor observes decrypted request paths, including HTTPS.
        fields = dict(src_ip=src_ip, dst_ip=host["ip"], dst_port=port,
                      host=host["fqdn"], method="GET", uri=uri,
                      status=status, response_bytes=0 if status >= 400 else 512)
        if user_agent:
            fields["user_agent"] = user_agent
        eid = self.emit("http", seconds, "web-app-01", **fields)
        if caused_by:
            self.links.append({"event_id": eid, "caused_by": caused_by})

    def service_query(self, seconds, src_ip, host, operation, result, caused_by=None):
        eid = self.emit("service_query", seconds, "smb-server-01", src_ip=src_ip,
                  dst_ip=host["ip"], dst_port=445, protocol="smb",
                  operation=operation, auth_context="domain-user", result=result)
        if caused_by:
            self.links.append({"event_id": eid, "caused_by": caused_by})

    def build(self):
        hosts = self.assets
        if self.family == "external":
            src = ENTITY_IPS["entity-external-scanner-01"]
            targets = [hosts[f"prod-web-{i:02d}"] for i in range(1, 5)]
            for ti, host in enumerate(targets):
                base = 3 + ti * 9
                for pi, port in enumerate((80, 443, 8080)):
                    self.connection(base + pi * 0.7, src, host, port, public=True, probe="syn")
            # A narrower follow-up on one responsive public web service.
            target = targets[1]
            outcome, parent = self.connection(43, src, target, 80, public=True)
            if outcome == "connected":
                for j, uri in enumerate(("/.env", "/docker/.env", "/local/.env")):
                    self.web(44 + j * 1.2, src, target, 80, uri, status=404,
                             public=True, caused_by=parent)
        elif self.family == "internal":
            source = hosts["prod-file-01"]
            self.process(1, source, "netscan.exe")
            for j, name in enumerate(("dc-01", "dc-02", "prod-file-02", "prod-rdp-01")):
                target = hosts[name]
                port = 445 if target["role"] in ("dc", "win") else 3389
                outcome, parent = self.connection(4 + j * 3, source["ip"], target, port)
                if outcome == "connected" and port == 445:
                    self.service_query(5 + j * 3, source["ip"], target,
                                       "enumerate_accessible_shares", "accessible" if j % 2 == 0 else "denied",
                                       caused_by=parent)
        elif self.family in ("nmap", "approved"):
            source = hosts["bastion-01"] if self.family == "nmap" else None
            src = source["ip"] if source else ENTITY_IPS["entity-approved-scanner-01"]
            if source and self.nmap_indicator == "explicit":
                self.process(1, source, "nmap")
            if self.family == "approved" and self.nmap_indicator == "explicit":
                # Its authorization exists only in the answer key/asset context.
                self.process(1, {"fqdn": "scanner-control.corp.example.local", "ip": src}, "nmap")
            if self.family == "nmap" and self.nmap_profile:
                profile = self.nmap_profile["measurements"]
                ports = list(profile["destination_ports"])
                self.rng.shuffle(ports)
                target = hosts["prod-web-01"]
                open_ports = set(profile["open_ports"])
                for j, port in enumerate(ports):
                    opened = port in open_ports
                    seconds = 3 + j * profile["probe_span_ms"] / (1000 * (len(ports) - 1))
                    delay = self.rng.triangular(0.002, 0.243, 0.05)
                    eid = self.emit("network_connection", seconds, "eastwest-fw-01",
                                    src_ip=src, dst_ip=target["ip"], dst_port=port,
                                    transport="tcp", probe_type="syn",
                                    outcome="answered" if opened else "rejected",
                                    packets=3 if opened else 2,
                                    bytes_out=120 if opened else 60,
                                    bytes_in=58 if opened else 54,
                                    duration_ms=round(delay, 3))
                    self.links.append({"event_id": eid, "target_asset": target["fqdn"],
                                       "target_asset_id": asset_id(target),
                                       "translated_destination": None})
            else:
                for j, name in enumerate(("prod-web-01", "prod-app-01", "prod-db-01", "dc-01")):
                    target = hosts[name]
                    for pi, port in enumerate((22, 80, 443, 445, 5432)):
                        self.connection(3 + j * 8 + pi * 0.9, src, target, port, probe="syn")
        else:
            raise ValueError(f"Unknown scenario family: {self.family}")
        # Each background session has a DNS lookup and two related page requests.
        client = hosts["dev-app-01"]
        for session_index, offset in enumerate(self.background_offsets):
            web = hosts[f"prod-web-{1 + session_index % 4:02d}"]
            cached = self.dns_cache.get(web["fqdn"])
            if cached is None or cached[0] <= offset:
                lookup = self.dns(offset, client, web["fqdn"],
                                  answers=(web["ip"],), ttls=(300,))
                self.dns_cache[web["fqdn"]] = (offset + 300, lookup)
            else:
                lookup = cached[1]
            outcome, parent = self.connection(offset + 1, client["ip"], web, 80)
            self.links.append({"event_id": parent, "resolved_by": lookup})
            if outcome == "connected":
                self.web(offset + 2, client["ip"], web, 80, "/", status=200, caused_by=parent)
                self.web(offset + 3, client["ip"], web, 80, "/status", status=200, caused_by=parent)
            diagnostic = (self.number + session_index) % 5
            if diagnostic == 0:
                self.dns(offset + 4, client, web["fqdn"], query_type="AAAA")
            elif diagnostic == 1:
                self.dns(offset + 4, client, f"missing-{self.number}.corp.example.local",
                         rcode="NXDOMAIN")
            elif diagnostic == 2:
                self.dns(offset + 4, client, f"transient-{self.number}.corp.example.local",
                         rcode="SERVFAIL")
            elif diagnostic == 3:
                self.dns(offset + 4, client, f"alias-{self.number}.corp.example.local",
                         query_type="CNAME", answers=(web["fqdn"],), ttls=(120,))
            else:
                name = f"delayed-{self.number}.corp.example.local"
                first = self.dns(offset + 4, client, name, rcode=None)
                retry = self.dns(offset + 4.5, client, name,
                                 answers=(web["ip"],), ttls=(60,))
                self.links.append({"event_id": retry, "retry_of": first})
        self.events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
        return self.events


def generate(seed, start, duration_minutes, campaign_count, endpoint=True, http=True,
             nmap_indicator="explicit", background_sessions_per_minute=None,
             nmap_profile="basic"):
    if not 1 <= campaign_count <= 100:
        raise ValueError("--campaign-count must be between 1 and 100")
    if duration_minutes < 4 * campaign_count:
        raise ValueError("--duration-minutes must allow at least four minutes per campaign set")
    if background_sessions_per_minute is not None and not 0 <= background_sessions_per_minute <= 10:
        raise ValueError("--background-sessions-per-minute must be between 0 and 10")
    if nmap_profile not in ("basic", "lab-syn-100"):
        raise ValueError("Unknown Nmap profile")
    profile_path = Path(__file__).resolve().parent / "catalogs" / "recon" / "nmap-syn-lab-v1.json"
    profile_bytes = profile_path.read_bytes() if nmap_profile == "lab-syn-100" else None
    profile_data = json.loads(profile_bytes) if profile_bytes else None
    assets = {h["short"]: h for h in build_hosts(random.Random(seed))}
    catalog_path = Path(__file__).resolve().parent / "catalogs" / "recon" / "evidence-v1.json"
    catalog_bytes = catalog_path.read_bytes()
    catalog_ids = {p["id"] for p in json.loads(catalog_bytes)["profiles"]}
    if any(not set(refs) <= catalog_ids for refs in EVIDENCE.values()):
        raise ValueError("Scenario references a missing evidence catalog entry")
    if profile_data and profile_data["id"] not in catalog_ids:
        raise ValueError("Nmap profile references a missing evidence catalog entry")
    manifest = {
        "schema_version": VERSION, "generator_version": VERSION, "seed": seed,
        "start_time": stamp(start), "duration_minutes": duration_minutes,
        "inventory_identity": "common/assets.py:default-23",
        "evidence_catalog": "catalogs/recon/evidence-v1.json",
        "evidence_catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
        "public_exposures": PUBLIC_IPS,
        "authorized_scanner_ip": ENTITY_IPS["entity-approved-scanner-01"],
        "service_catalog": {role: sorted(ports) for role, ports in SERVICES.items()},
        "sensor_config": {"endpoint": endpoint, "http": http},
        "background_sessions_per_minute": background_sessions_per_minute,
        "nmap_profile": nmap_profile,
        "nmap_profile_sha256": hashlib.sha256(profile_bytes).hexdigest() if profile_bytes else None,
        "operations": [], "omitted_observations": {},
    }
    step = duration_minutes * 60 / (4 * campaign_count)
    def events():
        omitted = Counter()
        for number in range(4 * campaign_count):
            family = FAMILIES[number % 4]
            if background_sessions_per_minute is None:
                offsets = (51,)
            else:
                sessions = round(background_sessions_per_minute * step / 60)
                offsets = tuple((i + 1) * (step - 4) / (sessions + 1) for i in range(sessions))
            op = Operation(seed, number, family, start + timedelta(seconds=number * step),
                           assets, endpoint, http, nmap_indicator, offsets,
                           profile_data if family == "nmap" else None)
            observations = op.build()
            omitted.update(op.omitted)
            source_ref = ({"entity_id": "entity-external-scanner-01"} if family == "external" else
                          {"entity_id": "entity-approved-scanner-01"} if family == "approved" else
                          {"asset_id": asset_id(assets["prod-file-01"])} if family == "internal" else
                          {"asset_id": asset_id(assets["bastion-01"])})
            manifest["operations"].append({
                "operation_id": f"operation-{number:04d}", "family": family,
                "start_time": stamp(op.start),
                "last_observation_at": observations[-1]["timestamp"] if observations else None,
                "source_ref": source_ref,
                "intent": "authorized" if family == "approved" else "simulated_unapproved",
                "authorization": family == "approved",
                "evidence_refs": EVIDENCE[family] + (["nmap-syn-lab-100"] if family == "nmap" and profile_data else []),
                "techniques": TECHNIQUES[family], "event_ids": [e["event_id"] for e in observations],
                "interaction_links": op.links,
                "intended_tool": "nmap" if family in ("nmap", "approved") else None,
                "source_ip": (ENTITY_IPS["entity-external-scanner-01"] if family == "external" else
                              ENTITY_IPS["entity-approved-scanner-01"] if family == "approved" else
                              assets["prod-file-01"]["ip"] if family == "internal" else
                              assets["bastion-01"]["ip"]),
                "expected_detection": ("contextual_suppression" if family == "approved" else
                                       "discovery_review"),
                "calibration_status": ("capture_calibrated" if family == "nmap" and profile_data
                                       else "documented_behavior_only"),
                "service_overrides": ({"prod-web-01": profile_data["measurements"]["open_ports"]}
                                      if family == "nmap" and profile_data else {}),
            })
            yield from observations
        manifest["omitted_observations"] = dict(omitted)
    return events(), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--start-time", required=True, help="ISO 8601 timestamp with timezone")
    parser.add_argument("--duration-minutes", type=int, default=60)
    parser.add_argument("--campaign-count", type=int, default=1)
    parser.add_argument("--background-sessions-per-minute", type=float,
                        help="Modeled browsing sessions/minute; default is one per operation")
    parser.add_argument("--nmap-indicator", choices=("explicit", "behavior-only"), default="explicit")
    parser.add_argument("--nmap-profile", choices=("basic", "lab-syn-100"), default="basic")
    parser.add_argument("--no-endpoint", action="store_true")
    parser.add_argument("--no-http-sensor", action="store_true")
    parser.add_argument("--output", default="output/recon-events.jsonl")
    parser.add_argument("--truth-output", default="output/recon-truth.json")
    parser.add_argument("--zeek-dns-output", help="Optional synthetic Zeek JSON dns.log output")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        start = datetime.fromisoformat(parse_times([args.start_time])[0].replace("Z", "+00:00"))
        paths = [Path(value).resolve() for value in
                 (args.output, args.truth_output, args.zeek_dns_output) if value]
        if len(paths) != len(set(paths)):
            raise ValueError("Output paths must differ")
        records, manifest = generate(args.seed, start, args.duration_minutes, args.campaign_count,
                                     not args.no_endpoint, not args.no_http_sensor, args.nmap_indicator,
                                     args.background_sessions_per_minute, args.nmap_profile)
        if args.zeek_dns_output:
            sessions_per_operation = (1 if args.background_sessions_per_minute is None else
                                      round(args.background_sessions_per_minute * args.duration_minutes /
                                            (4 * args.campaign_count)))
            if sessions_per_operation == 0:
                raise ValueError("Zeek DNS output requires background DNS sessions")
            manifest["dns_renderer"] = {
                "format": "Zeek JSON dns.log",
                "schema_reference": "https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html",
                "splunk_ta_validation": "not_performed",
            }
        counts = Counter()
        count = export_records(args.output, records, "jsonl", on_record=lambda e: counts.update([e["event_type"]]),
                               dry_run=args.dry_run)
        zeek_count = 0
        if args.zeek_dns_output:
            zeek_records, _ = generate(args.seed, start, args.duration_minutes, args.campaign_count,
                                       not args.no_endpoint, not args.no_http_sensor, args.nmap_indicator,
                                       args.background_sessions_per_minute, args.nmap_profile)
            zeek_count = export_records(args.zeek_dns_output,
                                        (render_dns(e) for e in zeek_records if e["event_type"] == "dns"),
                                        "jsonl", dry_run=args.dry_run)
            if zeek_count != counts["dns"]:
                raise ValueError("Zeek DNS and normalized DNS counts differ")
        if not args.dry_run:
            path = Path(args.truth_output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Generated {count} events: {dict(sorted(counts.items()))}")
        if args.zeek_dns_output:
            print(f"Rendered {zeek_count} Zeek DNS rows to {Path(args.zeek_dns_output).resolve()}")
        print(f"Omitted observations: {manifest['omitted_observations']}")
        if args.dry_run:
            print("Dry run; no files written")
        else:
            print(f"Wrote events to {Path(args.output).resolve()} and truth to {Path(args.truth_output).resolve()}")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
