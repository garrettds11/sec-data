import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import create_recon_events as recon
from common.zeek_dns import QUERY_TYPES, RESPONSE_CODES, render_dns


START = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)


class ZeekDnsTests(unittest.TestCase):
    def test_dns_protocol_states_and_zeek_projection(self):
        events, _ = recon.generate(42, START, 40, 2)
        dns = [event for event in events if event["event_type"] == "dns"]
        self.assertEqual(len(dns), 17)
        self.assertEqual(Counter(event["rcode"] for event in dns),
                         {"NOERROR": 12, "NXDOMAIN": 2, "SERVFAIL": 2, None: 1})
        ids = set()
        for event in dns:
            zeek = render_dns(event)
            self.assertNotIn(zeek["uid"], ids)
            ids.add(zeek["uid"])
            self.assertEqual(zeek["id.orig_h"], event["client_ip"])
            self.assertEqual(zeek["id.resp_h"], event["resolver_ip"])
            self.assertEqual(zeek["trans_id"], event["transaction_id"])
            self.assertEqual(zeek["qtype"], QUERY_TYPES[event["query_type"]])
            self.assertEqual(zeek["ts"],
                             datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp())
            self.assertFalse({"event_id", "synthetic", "sensor_id", "scenario_id"} & zeek.keys())
            if event["response_observed"]:
                self.assertEqual(zeek["rcode"], RESPONSE_CODES[event["rcode"]])
                self.assertGreater(zeek["rtt"], 0)
                self.assertEqual(zeek.get("answers", []), event["answers"])
                self.assertEqual(len(zeek.get("TTLs", [])), len(event["answers"]))
            else:
                self.assertFalse({"rcode", "rcode_name", "rtt", "answers", "TTLs", "RA"} & zeek.keys())
        self.assertTrue(any(e["query_type"] == "AAAA" and e["rcode"] == "NOERROR"
                            and not e["answers"] for e in dns))
        self.assertTrue(any(e["query_type"] == "CNAME" and e["answers"] for e in dns))
        timeout = next(e for e in dns if e["rcode"] is None)
        retry = next(e for e in dns if e["query"] == timeout["query"]
                     and e["rcode"] == "NOERROR")
        self.assertGreater(retry["timestamp"], timeout["timestamp"])

    def test_browsing_depends_on_successful_address_lookup(self):
        events, truth = recon.generate(42, START, 40, 2)
        by_id = {event["event_id"]: event for event in events}
        for operation in truth["operations"]:
            for link in operation["interaction_links"]:
                if "resolved_by" in link:
                    self.assertEqual(by_id[link["event_id"]]["event_type"], "network_connection")
                    self.assertEqual(by_id[link["resolved_by"]]["event_type"], "dns")
                if "retry_of" in link:
                    self.assertEqual(by_id[link["retry_of"]]["rcode"], None)
                    self.assertEqual(by_id[link["event_id"]]["rcode"], "NOERROR")
        browsing = [event for event in events if event["event_type"] == "http"
                    and event.get("uri") == "/"]
        for web in browsing:
            earlier = [event for event in events if event["event_type"] == "dns"
                       and event["rcode"] == "NOERROR" and web["dst_ip"] in event["answers"]
                       and event["timestamp"] < web["timestamp"]]
            self.assertTrue(earlier)

    def test_repeated_browsing_uses_modeled_dns_cache(self):
        events, _ = recon.generate(42, START, 4, 1, background_sessions_per_minute=10)
        rows = list(events)
        browsing = [e for e in rows if e["event_type"] == "http" and e.get("uri") == "/"
                    and e["src_ip"] != "203.0.113.50"]
        address_lookups = [e for e in rows if e["event_type"] == "dns"
                           and e["query_type"] == "A" and e["query"].startswith("prod-web-")]
        self.assertEqual(len(browsing), 40)
        self.assertEqual(len(address_lookups), 16)

    def test_cli_exports_zeek_jsonl_separately(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root = Path(tmp)
            normal = root / "events.jsonl"
            zeek = root / "dns.log"
            truth = root / "truth.json"
            command = [sys.executable, str(Path(recon.__file__)), "--seed", "42",
                       "--start-time", "2026-10-22T12:00:00Z", "--duration-minutes", "40",
                       "--campaign-count", "2", "--output", str(normal),
                       "--truth-output", str(truth), "--zeek-dns-output", str(zeek)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            events = [json.loads(line) for line in normal.read_text(encoding="utf-8").splitlines()]
            zeek_rows = [json.loads(line) for line in zeek.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(zeek_rows,
                             [render_dns(e) for e in events if e["event_type"] == "dns"])
            self.assertEqual(len(zeek_rows), 17)
            self.assertTrue(truth.exists())
            subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(zeek_rows,
                             [json.loads(line) for line in zeek.read_text(encoding="utf-8").splitlines()])


if __name__ == "__main__":
    unittest.main()
