from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import verify_ticket
from .load import load_json, summarize_caveats


def cmd_inspect(args: argparse.Namespace) -> int:
    ticket = load_json(args.ticket)
    doc = {
        "id": ticket.get("id"),
        "location": ticket.get("location"),
        "key_id": ticket.get("key_id"),
        "caveats": summarize_caveats(ticket.get("caveats") or []),
        "signature_hex_prefix": (ticket.get("signature_hex") or "")[:16],
    }
    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        ticket = load_json(args.ticket)
        request = load_json(args.request)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        discharges = []
        if args.discharge:
            for p in args.discharge:
                discharges.append(load_json(p))
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"load error: {e}", file=sys.stderr)
        return 2

    report = verify_ticket(ticket, request, keys, policy, discharges)
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    decision = report.get("decision")
    if decision == "allow":
        return 0
    if decision == "deny":
        return 1
    print("invalid report decision", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caveatgate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ins = sub.add_parser("inspect")
    p_ins.add_argument("--ticket", required=True)
    p_ins.set_defaults(func=cmd_inspect)

    p_ver = sub.add_parser("verify")
    p_ver.add_argument("--ticket", required=True)
    p_ver.add_argument("--request", required=True)
    p_ver.add_argument("--keys", required=True)
    p_ver.add_argument("--policy", required=True)
    p_ver.add_argument("--discharge", action="append", default=[])
    p_ver.add_argument("--report", required=True)
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
