from __future__ import annotations

from typing import Any


def verify_ticket(
    ticket: dict[str, Any],
    request: dict[str, Any],
    keys: dict[str, Any],
    policy: dict[str, Any],
    discharges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a report dict per docs/report-schema.md.

    Initial snapshot: intentionally incomplete. Inspect works; verify must be
    implemented against docs/verify-rules.md.
    """
    discharges = discharges or []
    return {
        "decision": "deny",
        "reason_codes": ["unknown_caveat"],
        "ticket_id": ticket.get("id"),
        "key_id": ticket.get("key_id"),
        "caveat_count": len(ticket.get("caveats") or []),
        "discharge_used": 0,
        "notes": ["engine.verify_ticket is not implemented in the initial snapshot"],
    }
