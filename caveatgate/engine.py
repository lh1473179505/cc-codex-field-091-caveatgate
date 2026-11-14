from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Any


def _unhex(value: str) -> bytes:
    return bytes.fromhex(value)


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _chain_signature(
    key: bytes,
    location: str,
    ticket_id: str,
    key_id: str,
    caveats: list[dict[str, Any]],
) -> bytes:
    """Recompute the chained HMAC-SHA256 signature defined in verify-rules.md."""
    msg0 = (
        location.encode("utf-8")
        + b"\x00"
        + ticket_id.encode("utf-8")
        + b"\x00"
        + key_id.encode("utf-8")
    )
    sig = _hmac(key, msg0)
    for caveat in caveats:
        ctype = caveat.get("type")
        cid = str(caveat.get("cid") or "")
        if ctype == "first":
            msg = sig + b"\x00" + b"first" + b"\x00" + cid.encode("utf-8")
        elif ctype == "third":
            msg = (
                sig
                + b"\x00"
                + b"third"
                + b"\x00"
                + cid.encode("utf-8")
                + b"\x00"
                + str(caveat.get("location") or "").encode("utf-8")
                + b"\x00"
                + _unhex(str(caveat.get("vid_hex") or ""))
            )
        else:
            raise ValueError(f"unknown caveat type: {ctype!r}")
        sig = _hmac(sig, msg)
    return sig


def _root_key_bytes(keys: dict[str, Any], key_id: str) -> bytes:
    roots = keys.get("roots")
    if not isinstance(roots, dict) or key_id not in roots:
        raise ValueError(f"required root key id absent: {key_id!r}")
    return _unhex(str(roots[key_id]))


def _discharge_key_bytes(keys: dict[str, Any], key_id: str) -> bytes | None:
    discharges = keys.get("discharges")
    if not isinstance(discharges, dict) or key_id not in discharges:
        return None
    entry = discharges[key_id]
    if not isinstance(entry, dict) or "key_hex" not in entry:
        return None
    return _unhex(str(entry["key_hex"]))


def _parse_instant(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _split_cid(cid: str) -> tuple[str, str]:
    head, separator, operand = cid.partition(" ")
    if not separator:
        return cid.strip(), ""
    operand = operand.lstrip()
    return head, operand


def _eval_first_party(cid: str, request: dict[str, Any]) -> str | None:
    """Return the failure reason code for a first-party cid, or None on pass."""
    head, operand = _split_cid(cid)
    if head == "time" and operand.startswith("< "):
        try:
            deadline = _parse_instant(operand[2:].lstrip())
            now = _parse_instant(str(request.get("now") or ""))
        except (ValueError, TypeError):
            return "unknown_caveat"
        if now >= deadline:
            return "expired"
        return None
    if head == "method" and operand.startswith("= "):
        if str(request.get("method")) != operand[2:]:
            return "method_mismatch"
        return None
    if head == "path" and operand.startswith("= "):
        if str(request.get("path")) != operand[2:]:
            return "path_mismatch"
        return None
    if head == "path_prefix" and operand.startswith("= "):
        prefix = operand[2:]
        if not str(request.get("path") or "").startswith(prefix):
            return "prefix_mismatch"
        return None
    if head == "account" and operand.startswith("= "):
        if str(request.get("account")) != operand[2:]:
            return "account_mismatch"
        return None
    return "unknown_caveat"


def _has_account_caveat(caveats: list[dict[str, Any]]) -> bool:
    for caveat in caveats:
        if caveat.get("type") != "first":
            continue
        head, _ = _split_cid(str(caveat.get("cid") or ""))
        if head == "account":
            return True
    return False


def verify_ticket(
    ticket: dict[str, Any],
    request: dict[str, Any],
    keys: dict[str, Any],
    policy: dict[str, Any],
    discharges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify a capability ticket and return a report per docs/report-schema.md."""
    discharges = list(discharges or [])
    caveats: list[dict[str, Any]] = list(ticket.get("caveats") or [])
    key_id = str(ticket.get("key_id") or "")
    location = str(ticket.get("location") or "")
    ticket_id = str(ticket.get("id") or "")

    reasons: list[str] = []

    def add_reason(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    # Step 1-2: root key lookup (load failure when absent) + ticket chain.
    root_key = _root_key_bytes(keys, key_id)
    try:
        computed_sig = _chain_signature(
            root_key, location, ticket_id, key_id, caveats
        )
        stored_sig = _unhex(str(ticket.get("signature_hex") or ""))
        sig_ok = hmac.compare_digest(computed_sig, stored_sig)
    except (ValueError, TypeError):
        sig_ok = False
    if not sig_ok:
        add_reason("bad_signature")

    # Step 3: ticket first-party caveats.
    if sig_ok:
        for caveat in caveats:
            if caveat.get("type") == "first":
                code = _eval_first_party(str(caveat.get("cid") or ""), request)
                if code is not None:
                    add_reason(code)

    # Step 4: third-party caveats and their discharges.
    discharge_used = 0
    if sig_ok and not reasons:
        available = list(range(len(discharges)))
        discharge_keys = keys.get("discharges")
        known_key_ids = (
            list(discharge_keys.keys())
            if isinstance(discharge_keys, dict)
            else []
        )
        for caveat in caveats:
            if caveat.get("type") != "third":
                continue
            cid = str(caveat.get("cid") or "")
            third_location = str(caveat.get("location") or "")
            vid_hex = str(caveat.get("vid_hex") or "")

            derived_key_id = ""
            try:
                vid_bytes = _unhex(vid_hex)
            except ValueError:
                vid_bytes = b""
            for candidate_id in known_key_ids:
                preimage = (
                    b"vid|"
                    + cid.encode("utf-8")
                    + b"|"
                    + candidate_id.encode("utf-8")
                )
                if vid_bytes and hmac.compare_digest(
                    _hmac(root_key, preimage), vid_bytes
                ):
                    derived_key_id = candidate_id
                    break

            match_index = None
            if derived_key_id:
                for index in available:
                    discharge = discharges[index]
                    if discharge.get("location") != third_location:
                        continue
                    if str(discharge.get("key_id") or "") != derived_key_id:
                        continue
                    match_index = index
                    break

            if match_index is None:
                add_reason("missing_discharge")
                continue

            available.remove(match_index)
            discharge = discharges[match_index]
            discharge_key = _discharge_key_bytes(keys, derived_key_id)
            if discharge_key is None:
                add_reason("missing_discharge")
                continue

            try:
                discharge_sig = _chain_signature(
                    discharge_key,
                    str(discharge.get("location") or ""),
                    str(discharge.get("id") or ""),
                    str(discharge.get("key_id") or ""),
                    list(discharge.get("caveats") or []),
                )
                discharge_stored = _unhex(
                    str(discharge.get("signature_hex") or "")
                )
                discharge_sig_ok = hmac.compare_digest(
                    discharge_sig, discharge_stored
                )
            except (ValueError, TypeError):
                discharge_sig_ok = False
            if not discharge_sig_ok:
                add_reason("bad_discharge_signature")
                continue

            discharge_failed = False
            for discharge_caveat in discharge.get("caveats") or []:
                if discharge_caveat.get("type") != "first":
                    add_reason("unknown_caveat")
                    discharge_failed = True
                    break
                code = _eval_first_party(
                    str(discharge_caveat.get("cid") or ""), request
                )
                if code is not None:
                    add_reason(code)
                    discharge_failed = True
                    break
            if discharge_failed:
                continue

            bound = _hmac(discharge_sig, computed_sig).hex()
            if not hmac.compare_digest(
                str(discharge.get("binding_hex") or ""), bound
            ):
                add_reason("unbound_discharge")
                continue

            discharge_used += 1

    # Step 6: policy checks.
    if not reasons:
        max_caveats = policy.get("max_caveats")
        if isinstance(max_caveats, int) and len(caveats) > max_caveats:
            add_reason("too_many_caveats")
        allowed_locations = policy.get("allowed_locations")
        if isinstance(allowed_locations, list) and location not in allowed_locations:
            add_reason("location_denied")
        if policy.get("require_account_caveat") and not _has_account_caveat(caveats):
            add_reason("account_caveat_required")

    return {
        "decision": "allow" if not reasons else "deny",
        "reason_codes": reasons,
        "ticket_id": ticket.get("id"),
        "key_id": ticket.get("key_id"),
        "caveat_count": len(caveats),
        "discharge_used": discharge_used,
    }
