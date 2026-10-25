"""Explicit, source-aware CIM field projections for synthetic observations.

These are index-ready field values, not claims of Splunk data-model membership.
"""

from datetime import datetime, timezone
from pathlib import PureWindowsPath


CIM_VERSION = "8.8"

# Only observational files appear here. World catalogs, scenario truth, and
# compliance assessments are intentionally outside these event mappings.
SOURCES = (
    "vulnerability.jsonl", "vulnerability-followup.jsonl", "recon.jsonl",
    "dns.log", "ingress-firewall.jsonl", "ingress-zeek-conn.jsonl",
    "ingress-zeek-http.jsonl", "edge-proxy.jsonl", "web-auth.jsonl",
    "windows-security.jsonl", "sysmon.jsonl", "windows-file.jsonl",
    "zeek-conn.jsonl", "zeek-http.jsonl", "egress-firewall.jsonl",
    "alerts.jsonl", "case-actions.jsonl", "response-firewall.jsonl",
)


def _time(value):
    if isinstance(value, (float, int)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if not value:
        raise ValueError("Observation has no event time")
    return value


def _put(out, row, **fields):
    for name, key in fields.items():
        if key in row and row[key] is not None:
            out[name] = row[key]


def _zeek_flow(out, row):
    _put(out, row, src="id.orig_h", src_port="id.orig_p", dest="id.resp_h",
         dest_port="id.resp_p", transport="proto", session_id="uid")


def _dns_reply(value):
    return {"NOERROR": "No Error", "NXDOMAIN": "Non-Existent Domain",
            "SERVFAIL": "Server Failure", "FORMERR": "Format Error"}.get(value, value)


def project(source, row):
    """Return one CIM-shaped observation, or None for an unsupported subtype."""
    if source not in SOURCES:
        raise ValueError(f"Unsupported CIM source: {source}")
    observed_at = row.get("timestamp", row.get("time", row.get(
        "TimeCreated", row.get("fired_at", row.get("assessment_at", row.get(
            "last_seen", row.get("ts")))))))
    if source.startswith("vulnerability") and row.get("assessment_id", "").startswith("synthetic-"):
        observed_at = row["assessment_id"].split("-", 2)[2]
    out = {"time": _time(observed_at), "synthetic": True,
           "sec_data_source": source}
    if source == "recon.jsonl":
        kind = row["event_type"]
        if kind == "dns":
            model = "Network_Resolution.DNS"
            _put(out, row, src="client_ip", src_port="client_port", dest="resolver_ip",
                 dest_port="resolver_port", query="query", query_type="query_type",
                 answer="answers", transaction_id="transaction_id", transport="transport")
            out["answer_count"] = len(row.get("answers", []))
            if row.get("rcode") is not None:
                out["reply_code"] = _dns_reply(row["rcode"])
            if row.get("response_time_ms") is not None:
                out["response_time"] = row["response_time_ms"] / 1000
            if row.get("answer_ttls"):
                out["ttl"] = row["answer_ttls"]
        elif kind == "network_connection":
            model = "Network_Traffic.All_Traffic"
            _put(out, row, src="src_ip", dest="dst_ip", dest_port="dst_port",
                 transport="transport", bytes_in="bytes_in", bytes_out="bytes_out",
                 packets="packets")
            out["bytes"] = row.get("bytes_in", 0) + row.get("bytes_out", 0)
            if row.get("duration_ms") is not None:
                out["duration"] = row["duration_ms"] / 1000
            if row.get("outcome") in ("answered", "connected"):
                out["action"] = "allowed"
            elif row.get("outcome") == "blocked":
                out["action"] = "blocked"
            out["connection_result"] = row.get("outcome")
            _put(out, row, probe_type="probe_type")
        elif kind == "http":
            model = "Web.Web"
            _put(out, row, src="src_ip", dest="dst_ip", dest_port="dst_port",
                 http_method="method", status="status", bytes_out="response_bytes")
            out["url"] = f"{row['host']}{row['uri']}" if row.get("host") else row.get("uri")
        elif kind == "process":
            model = "Endpoint.Processes"
            _put(out, row, dest="host_name", process="executable", process_id="process_id",
                 user="user")
        else:
            return None  # Service query is a modeled observation without a sound CIM fit.
        _put(out, row, event_id="event_id", dvc="sensor_id")
    elif source == "dns.log":
        model = "Network_Resolution.DNS"
        _zeek_flow(out, row)
        _put(out, row, query="query", query_type="qtype_name", answer="answers",
             transaction_id="trans_id", response_time="rtt")
        out["answer_count"] = len(row.get("answers", []))
        if row.get("rcode_name") is not None:
            out["reply_code"] = _dns_reply(row["rcode_name"])
            _put(out, row, reply_code_id="rcode")
        if row.get("TTLs"):
            out["ttl"] = row["TTLs"]
    elif source.startswith("vulnerability"):
        model = "Vulnerabilities.Vulnerabilities"
        _put(out, row, dest="host_name", dest_ip="host_ip",
             cvss="vulnerability_score_base", severity="vulnerability_severity",
             signature="title", signature_id="scanner_plugin_id",
             description="vulnerability_description", status="vulnerability_status",
             dest_port="network_port", transport="network_protocol", asset_id="asset_id",
             finding_id="finding_id")
        out["severity"] = {"info": "informational"}.get(out["severity"].lower(), out["severity"].lower())
        if row["vulnerability_id"].startswith("CVE-"):
            out["cve"] = row["vulnerability_id"]
        if row.get("vulnerability_category"):
            out["category"] = ", ".join(row["vulnerability_category"])
        out["vendor_product"] = row.get("vulnerability_scanner_vendor", "Synthetic scanner")
    elif source in ("ingress-firewall.jsonl", "egress-firewall.jsonl", "response-firewall.jsonl"):
        model = "Network_Traffic.All_Traffic"
        _put(out, row, src="src_ip", src_port="src_port", dest="dest_ip", dest_port="dest_port",
             transport="protocol", bytes_in="bytes_in", bytes_out="bytes_out",
             rule="rule", dvc="device")
        out["action"] = {"allow": "allowed", "block": "blocked"}.get(row["action"], row["action"])
        out["bytes"] = row.get("bytes_in", 0) + row.get("bytes_out", 0)
    elif source in ("ingress-zeek-conn.jsonl", "zeek-conn.jsonl"):
        model = "Network_Traffic.All_Traffic"
        _zeek_flow(out, row)
        _put(out, row, bytes_in="orig_ip_bytes", bytes_out="resp_ip_bytes",
             duration="duration", app="service", connection_state="conn_state")
        out["bytes"] = row.get("orig_ip_bytes", 0) + row.get("resp_ip_bytes", 0)
    elif source in ("ingress-zeek-http.jsonl", "zeek-http.jsonl"):
        model = "Web.Web"
        _zeek_flow(out, row)
        _put(out, row, http_method="method", status="status_code",
             bytes_in="request_body_len", bytes_out="response_body_len")
        out["url"] = f"{row['host']}{row['uri']}" if row.get("host") else row.get("uri")
    elif source == "edge-proxy.jsonl":
        model = "Web.Web"
        _put(out, row, src="client_ip", dest="server_ip", dest_port="server_port",
             http_method="method", status="status", bytes_out="response_bytes")
        out["url"] = f"{row['host']}{row['uri']}"
        out["action"] = row["waf_action"]
    elif source == "web-auth.jsonl":
        if row.get("event") != "login":
            return None
        model = "Authentication.Authentication"
        _put(out, row, src="client_ip", dest="server_name", user="account",
             action="outcome", reason="reason", session_id="request_id")
        out["app"] = "web"
    elif source == "windows-security.jsonl":
        if row["EventCode"] in (4624, 4625):
            model = "Authentication.Authentication"
            _put(out, row, src="IpAddress", dest="Computer", user="TargetUserName",
                 src_nt_domain="TargetDomainName", session_id="TargetLogonId",
                 signature_id="EventCode")
            out["action"] = "success" if row["EventCode"] == 4624 else "failure"
        elif row["EventCode"] == 4728:
            model = "Change.All_Changes"
            out["sec_data_cim_subdataset"] = "Account_Management"
            _put(out, row, dest="Computer", src_user="SubjectUserName",
                 user="MemberName", object="TargetUserName",
                 signature_id="EventCode")
            out["action"] = "modified"
        else:
            return None
        out["event_id"] = f"security-{row['Computer']}-{row['EventRecordID']}"
    elif source == "sysmon.jsonl":
        code = row["EventCode"]
        if code in (1, 5):
            model = "Endpoint.Processes"
            _put(out, row, dest="Computer", user="User", process="Image",
                 process_id="ProcessId", process_guid="ProcessGuid", parent_process="ParentImage",
                 parent_process_id="ParentProcessId", process_cmdline="CommandLine")
            out["action"] = "created" if code == 1 else "terminated"
        elif code == 3:
            model = "Network_Traffic.All_Traffic"
            _put(out, row, src="SourceIp", src_port="SourcePort", dest="DestinationIp",
                 dest_port="DestinationPort", transport="Protocol", process="Image")
            out["action"] = "allowed"
        elif code == 11:
            model = "Endpoint.Filesystem"
            _put(out, row, dest="Computer", user="User", file_path="TargetFilename",
                 process="Image")
            out["action"] = "created"
        elif code == 13:
            model = "Endpoint.Registry"
            _put(out, row, dest="Computer", user="User", registry_path="TargetObject",
                 registry_value_data="Details", process="Image")
            out["action"] = "modified"
        else:
            return None
        out["event_id"] = f"sysmon-{row['Computer']}-{row['EventRecordID']}"
    elif source == "windows-file.jsonl":
        model = "Data_Access.Data_Access"
        _put(out, row, dest="Computer", src="IpAddress", user="SubjectUserName",
             object_path="ObjectName", object_category="ObjectType", process="ProcessName",
             signature_id="EventCode")
        if row["EventCode"] == 5145:
            out["object_path"] = row.get("ShareLocalPath", "") + "\\" + row["RelativeTargetName"]
        out["object"] = PureWindowsPath(out["object_path"]).name
        out["object_category"] = "file"
        out["action"] = "read"
        out["event_id"] = f"file-{row['Computer']}-{row['EventRecordID']}"
    elif source == "alerts.jsonl":
        model = "Alerts.Alerts"
        _put(out, row, event_id="alert_id", id="alert_id", signature="title", signature_id="rule_id",
             severity="severity")
        out["description"] = row["title"]
        out["app"] = "sec-data detector"
    elif source == "case-actions.jsonl":
        model = "TicketManagement.All_Ticket_Management"
        _put(out, row, ticket_id="case_id", status="status", action="action",
             event_id="action_id")
    else:
        raise AssertionError(source)
    out["sec_data_cim_dataset"] = model
    return out
