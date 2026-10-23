"""Render a modeled DNS observation in Zeek's JSON dns.log field format."""

from datetime import datetime


QUERY_TYPES = {"A": 1, "CNAME": 5, "AAAA": 28}
RESPONSE_CODES = {"NOERROR": 0, "SERVFAIL": 2, "NXDOMAIN": 3}


def render_dns(event):
    if event["event_type"] != "dns":
        raise ValueError("Expected a DNS observation")
    query_type = event["query_type"]
    if query_type not in QUERY_TYPES:
        raise ValueError(f"Unsupported DNS query type: {query_type}")
    rcode = event["rcode"]
    if rcode not in (*RESPONSE_CODES, None):
        raise ValueError(f"Unsupported DNS response code: {rcode}")
    if len(event["answers"]) != len(event["answer_ttls"]):
        raise ValueError("DNS answers and TTLs must have the same length")
    if event["response_observed"] != (rcode is not None):
        raise ValueError("DNS response state and response code disagree")
    if rcode != "NOERROR" and event["answers"]:
        raise ValueError("Unsuccessful DNS queries cannot have answers")

    result = {
        "ts": datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp(),
        "uid": "C" + event["event_id"][:16],
        "id.orig_h": event["client_ip"],
        "id.orig_p": event["client_port"],
        "id.resp_h": event["resolver_ip"],
        "id.resp_p": event["resolver_port"],
        "proto": event["transport"],
        "trans_id": event["transaction_id"],
        "query": event["query"],
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": QUERY_TYPES[query_type],
        "qtype_name": query_type,
        "RD": True,
        "Z": 0,
        "opcode": 0,
        "opcode_name": "query",
    }
    if event["response_observed"]:
        result.update(rcode=RESPONSE_CODES[rcode], rcode_name=rcode,
                      rtt=event["response_time_ms"] / 1000,
                      AA=False, TC=False, RA=True, rejected=False)
        if event["answers"]:
            result["answers"] = event["answers"]
            result["TTLs"] = [float(ttl) for ttl in event["answer_ttls"]]
    return result
