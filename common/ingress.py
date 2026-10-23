"""Selected public and internal web interactions viewed from distinct sensors."""

import hashlib
from datetime import datetime, timedelta, timezone

from common.world import ENTITY_IPS, PUBLIC_IPS


VERSION = "1.0"


def parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def generate(events, truth, assets):
    """Render one blocked public probe and three observed web interactions."""
    by_id = {row["event_id"]: row for row in events}
    by_ip = {row["ip"]: row for row in assets}
    by_name = {row["fqdn"]: row for row in assets}
    parent_by_http = {link["event_id"]: link["caused_by"]
                      for op in truth["operations"] for link in op["interaction_links"]
                      if "caused_by" in link and by_id[link["event_id"]]["event_type"] == "http"}
    external_ip = ENTITY_IPS["entity-external-scanner-01"]
    public_http = [row for row in by_id.values() if row["event_type"] == "http" and
                   row["src_ip"] == external_ip]
    suspicious = next(row for row in public_http if row["uri"] == "/.env")
    secure = next(row for row in public_http if row["dst_port"] == 443)
    benign = next(row for row in by_id.values() if row["event_type"] == "http" and
                  row["src_ip"] in by_ip and row["uri"] == "/")
    blocked = next(row for row in by_id.values() if row["event_type"] == "network_connection" and
                   row["src_ip"] == external_ip and row["dst_port"] == 8080 and
                   row["outcome"] == "blocked")
    chosen = [suspicious, secure, benign]
    firewall, conn, http, ssl, proxy, interactions = [], [], [], [], [], []

    def add_connection(network, application=None):
        target = by_name[application["host"]] if application else by_ip.get(
            next(link["translated_destination"] for op in truth["operations"]
                 for link in op["interaction_links"] if link["event_id"] == network["event_id"]))
        if target is None:
            raise ValueError("Ingress target asset is missing")
        public = network["sensor_id"] == "perimeter-fw-01"
        public_ip = PUBLIC_IPS[target["short_name"]] if public else target["ip"]
        if network["dst_ip"] != public_ip:
            raise ValueError("Ingress public destination differs from inventory")
        uid = "C" + hashlib.sha256(network["event_id"].encode()).hexdigest()[:16]
        source_port = 52000 + int(network["event_id"][:4], 16) % 10000
        when = parse(network["timestamp"])
        allowed = network["outcome"] == "connected" and application is not None
        response = application["response_bytes"] if allowed else 0
        request_bytes = 180 + len(application["uri"]) if allowed else 0
        inbound_bytes = 120 + response if allowed else 0
        fw = {"time": network["timestamp"], "collected_at": network["collected_at"],
              "device": network["sensor_id"], "src_ip": network["src_ip"],
              "src_port": source_port, "dest_ip": network["dst_ip"],
              "translated_dest_ip": target["ip"] if allowed else None,
              "dest_port": network["dst_port"], "protocol": "tcp",
              "action": "allow" if allowed else "block",
              "bytes_out": request_bytes if allowed else network["bytes_out"],
              "bytes_in": inbound_bytes, "rule": "published-web" if allowed else "deny-unpublished-port"}
        firewall.append(fw)
        link = {"network_event_id": network["event_id"], "application_event_id":
                application["event_id"] if application else None, "firewall_index": len(firewall)-1,
                "target_asset_id": target["asset_id"], "source_ip": network["src_ip"],
                "public_destination": public_ip if public else None,
                "translated_destination": target["ip"] if allowed else None,
                "zeek_uid": uid if allowed else None, "at": network["timestamp"]}
        if not allowed:
            interactions.append(link)
            return
        conn.append({"ts": round(when.timestamp(), 3), "uid": uid,
                     "id.orig_h": network["src_ip"], "id.orig_p": source_port,
                     "id.resp_h": target["ip"], "id.resp_p": network["dst_port"],
                     "proto": "tcp", "service": "ssl" if network["dst_port"] == 443 else "http",
                     "duration": round((parse(application["timestamp"]) - when).total_seconds() + 0.2, 3),
                     "orig_ip_bytes": request_bytes, "resp_ip_bytes": inbound_bytes,
                     "conn_state": "SF", "local_orig": network["src_ip"] in by_ip,
                     "local_resp": True})
        if network["dst_port"] == 443:
            ssl.append({"ts": round((when + timedelta(milliseconds=20)).timestamp(), 3),
                        "uid": uid, "id.orig_h": network["src_ip"],
                        "id.orig_p": source_port, "id.resp_h": target["ip"],
                        "id.resp_p": 443, "version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256",
                        "server_name": target["fqdn"], "established": True,
                        "resumed": False, "next_protocol": "http/1.1"})
        else:
            http.append({"ts": round(parse(application["timestamp"]).timestamp(), 3),
                         "uid": uid, "id.orig_h": network["src_ip"],
                         "id.orig_p": source_port, "id.resp_h": target["ip"],
                         "id.resp_p": 80, "method": application["method"],
                         "host": application["host"], "uri": application["uri"],
                         "version": "1.1", "status_code": application["status"],
                         "request_body_len": 0,
                         "response_body_len": response})
        proxy.append({"time": application["timestamp"],
                      "collected_at": application["collected_at"],
                      "client_ip": network["src_ip"], "server_ip": target["ip"],
                      "server_port": network["dst_port"], "host": application["host"],
                      "method": application["method"], "uri": application["uri"],
                      "status": application["status"], "response_bytes": response,
                      "waf_action": "log" if application["uri"].endswith(".env") else "allow",
                      "waf_rule": "sensitive-path" if application["uri"].endswith(".env") else None})
        link["proxy_index"] = len(proxy)-1
        interactions.append(link)

    for app in chosen:
        add_connection(by_id[parent_by_http[app["event_id"]]], app)
    add_connection(blocked)
    firewall.sort(key=lambda row: row["time"])
    # Recompute positional references after sorting source files.
    for link in interactions:
        network = by_id[link["network_event_id"]]
        link["firewall_index"] = next(i for i, row in enumerate(firewall)
                                      if row["time"] == network["timestamp"] and
                                      row["src_ip"] == network["src_ip"] and
                                      row["dest_port"] == network["dst_port"])
    conn.sort(key=lambda row: row["ts"])
    http.sort(key=lambda row: row["ts"])
    ssl.sort(key=lambda row: row["ts"])
    proxy.sort(key=lambda row: row["time"])
    for link in interactions:
        if link["application_event_id"]:
            app = by_id[link["application_event_id"]]
            link["proxy_index"] = next(i for i, row in enumerate(proxy)
                                       if row["time"] == app["timestamp"] and
                                       row["uri"] == app["uri"] and
                                       row["client_ip"] == app["src_ip"])
    interactions.sort(key=lambda row: row["at"])
    return {"firewall": firewall, "conn": conn, "http": http,
            "ssl": ssl, "proxy": proxy,
            "truth": {"schema_version": VERSION, "interactions": interactions,
                      "notes": ["Zeek observes TLS metadata, not encrypted paths",
                                "Firewall byte counts are modeled after request completion"]}}
