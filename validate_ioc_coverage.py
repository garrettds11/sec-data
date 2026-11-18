#!/usr/bin/env python3
"""Verify promised publication IOCs in events/*.jsonl; exit nonzero on missing IOCs."""

import argparse
import json
from pathlib import Path

from common.ioc_coverage import check_dataset


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--coverage-file", required=True)
    parser.add_argument("--output", help="Optional NEW JSON report path; no file written by default")
    args = parser.parse_args(argv)
    try:
        report = check_dataset(args.dataset_dir, args.coverage_file)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            # Exclusive create protects previous reports and dataset files.
            with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            summary = {key: value for key, value in report.items() if key != "assertions"}
            summary["report_path"] = str(Path(args.output).resolve())
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(rendered, end="")
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    return 1 if report["missing"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
