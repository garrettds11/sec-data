#!/usr/bin/env python3
"""Inspect authoring inputs or validate a scenario without generating an event package."""

import argparse
import json

from common.assets import DEFAULT_HOST_COUNT, MAX_HOST_COUNT
from common.identity import iter_identities
from common.scenario import (ARRAY_FIELDS, FORBIDDEN, INTEGER_FIELDS, NUMBER_FIELDS,
                             REQUIRED, RESERVED, SCHEMA_VERSION, SOURCE_DATASETS,
                             STRING_FIELDS, load_scenario, merge_scenario_entities,
                             validate_scenario)
from common.world import iter_assets, iter_entities, iter_relationships


def describe_contract():
    return {
        "schema_version": SCHEMA_VERSION,
        "source_datasets": {key: sorted(value) for key, value in sorted(SOURCE_DATASETS.items())},
        "required_fields": {key: sorted(value) for key, value in sorted(REQUIRED.items())},
        "field_types": {"nonempty_string": sorted(STRING_FIELDS),
                        "nonnegative_integer": sorted(INTEGER_FIELDS),
                        "nonnegative_finite_number": sorted(NUMBER_FIELDS),
                        "nonempty_string_or_nonzero_integer": ["signature_id", "status"],
                        "array": {key: value.__name__ for key, value in ARRAY_FIELDS.items()}},
        "reserved_fields": sorted(RESERVED), "truth_only_fields": sorted(FORBIDDEN),
        "additional_rules": ["Authentication action: success or failure",
                             "Network action: allowed or blocked",
                             "When all byte fields are supplied, bytes = bytes_in + bytes_out",
                             "See docs/scenarios.md for JSON structure and timing rules"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scenario-file", help="Scenario JSON to validate")
    mode.add_argument("--describe-contract", action="store_true", help="Print supported fields and source/dataset pairs")
    mode.add_argument("--describe-context", action="store_true", help="Print the seeded inventory, identities and services")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--host-count", type=int, default=DEFAULT_HOST_COUNT)
    parser.add_argument("--duration-minutes", type=int, default=60)
    parser.add_argument("--target-events", type=int, help="Optional intended total; must cover all prescribed observations")
    args = parser.parse_args(argv)
    try:
        if not DEFAULT_HOST_COUNT <= args.host_count <= MAX_HOST_COUNT:
            raise ValueError(f"--host-count must be between {DEFAULT_HOST_COUNT} and {MAX_HOST_COUNT}")
        if args.describe_contract:
            result = describe_contract()
        else:
            assets, entities = list(iter_assets(args.seed, args.host_count)), list(iter_entities())
            identities = list(iter_identities())
            if args.describe_context:
                result = {"seed": args.seed, "assets": assets, "identities": identities,
                          "entities": entities, "relationships": list(iter_relationships(args.seed, args.host_count))}
            else:
                spec = load_scenario(args.scenario_file)
                entities = merge_scenario_entities(spec, assets, entities)
                result = validate_scenario(spec, args.duration_minutes, assets, entities, identities)
                if args.target_events is not None and args.target_events < result["prescribed_observations"]:
                    raise ValueError(f"--target-events must be at least {result['prescribed_observations']}")
                result.update(status="valid", seed=args.seed, host_count=args.host_count,
                              duration_minutes=args.duration_minutes, dataset_generated=False,
                              limitation="Structural compatibility only; review source fidelity, privileges, sensor coverage and causal plausibility separately")
        print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
