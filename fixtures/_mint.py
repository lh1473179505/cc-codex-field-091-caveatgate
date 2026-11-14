#!/usr/bin/env python3
"""Mint signed ticket fixtures for the initial snapshot. Not part of runtime API."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYS = json.loads((ROOT / "fixtures/keys.json").read_text())


def bhex(b: bytes) -> str:
    return b.hex()


def unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def root_key(kid: str) -> bytes:
    return unhex(KEYS["roots"][kid])


def discharge_key(kid: str) -> bytes:
    return unhex(KEYS["discharges"][kid]["key_hex"])


def sign_chain(key: bytes, location: str, tid: str, key_id: str, caveats: list[dict]) -> str:
    msg0 = location.encode() + b"\x00" + tid.encode() + b"\x00" + key_id.encode()
    sig = hmac.new(key, msg0, hashlib.sha256).digest()
    for c in caveats:
        if c["type"] == "first":
            msg = sig + b"\x00" + b"first" + b"\x00" + c["cid"].encode()
        elif c["type"] == "third":
            msg = (
                sig
                + b"\x00"
                + b"third"
                + b"\x00"
                + c["cid"].encode()
                + b"\x00"
                + c["location"].encode()
                + b"\x00"
                + unhex(c["vid_hex"])
            )
        else:
            raise ValueError(c)
        sig = hmac.new(sig, msg, hashlib.sha256).digest()
    return bhex(sig)


def make_vid(root: bytes, cid: str, discharge_key_id: str) -> str:
    pre = b"vid|" + cid.encode() + b"|" + discharge_key_id.encode()
    return bhex(hmac.new(root, pre, hashlib.sha256).digest())


def write_case(name: str, ticket: dict, request: dict, discharges: list[dict] | None = None):
    d = ROOT / "fixtures/cases" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "ticket.json").write_text(json.dumps(ticket, indent=2) + "\n")
    (d / "request.json").write_text(json.dumps(request, indent=2) + "\n")
    if discharges:
        for i, dis in enumerate(discharges):
            (d / f"discharge{i+1}.json").write_text(json.dumps(dis, indent=2) + "\n")


def main() -> None:
    rk = root_key("root-a")
    req_ok = {
        "method": "GET",
        "path": "/v1/orders/42",
        "account": "ACC-9",
        "now": "2026-04-01T12:00:00Z",
    }

    # ok-basic
    caveats = [
        {"type": "first", "cid": "time < 2026-04-02T00:00:00Z"},
        {"type": "first", "cid": "method = GET"},
        {"type": "first", "cid": "path_prefix = /v1/"},
        {"type": "first", "cid": "account = ACC-9"},
    ]
    t = {
        "id": "tkt-basic",
        "location": "https://auth.example/gate",
        "key_id": "root-a",
        "caveats": caveats,
        "signature_hex": sign_chain(rk, "https://auth.example/gate", "tkt-basic", "root-a", caveats),
    }
    write_case("ok-basic", t, req_ok)

    # ok-third-party
    vid = make_vid(rk, "need-otp", "otp-1")
    caveats_tp = [
        {"type": "first", "cid": "time < 2026-04-02T00:00:00Z"},
        {"type": "first", "cid": "method = GET"},
        {"type": "first", "cid": "path = /v1/orders/42"},
        {"type": "first", "cid": "account = ACC-9"},
        {
            "type": "third",
            "cid": "need-otp",
            "vid_hex": vid,
            "location": "https://otp.example/discharge",
        },
    ]
    t2 = {
        "id": "tkt-tp",
        "location": "https://auth.example/gate",
        "key_id": "root-a",
        "caveats": caveats_tp,
        "signature_hex": sign_chain(rk, "https://auth.example/gate", "tkt-tp", "root-a", caveats_tp),
    }
    dk = discharge_key("otp-1")
    d_caveats = [{"type": "first", "cid": "time < 2026-04-02T00:00:00Z"}]
    dis = {
        "id": "dis-1",
        "location": "https://otp.example/discharge",
        "key_id": "otp-1",
        "caveats": d_caveats,
        "signature_hex": sign_chain(
            dk, "https://otp.example/discharge", "dis-1", "otp-1", d_caveats
        ),
    }
    # binding
    bound = hmac.new(bytes.fromhex(dis["signature_hex"]), bytes.fromhex(t2["signature_hex"]), hashlib.sha256).hexdigest()
    dis_bundle = {**dis, "binding_hex": bound}
    write_case("ok-third-party", t2, req_ok, [dis_bundle])

    # deny-bad-sig
    bad = dict(t)
    bad["id"] = "tkt-badsig"
    bad["signature_hex"] = "00" * 32
    write_case("deny-bad-sig", bad, req_ok)

    # deny-expired
    caveats_exp = [
        {"type": "first", "cid": "time < 2026-03-01T00:00:00Z"},
        {"type": "first", "cid": "method = GET"},
        {"type": "first", "cid": "path_prefix = /v1/"},
        {"type": "first", "cid": "account = ACC-9"},
    ]
    texp = {
        "id": "tkt-exp",
        "location": "https://auth.example/gate",
        "key_id": "root-a",
        "caveats": caveats_exp,
        "signature_hex": sign_chain(rk, "https://auth.example/gate", "tkt-exp", "root-a", caveats_exp),
    }
    write_case("deny-expired", texp, req_ok)

    # deny-unbound-discharge (same as ok-third-party but wrong binding)
    dis_unbound = {**dis, "binding_hex": "11" * 32}
    write_case("deny-unbound-discharge", t2, req_ok, [dis_unbound])

    # deny-unknown-caveat
    caveats_u = [
        {"type": "first", "cid": "time < 2026-04-02T00:00:00Z"},
        {"type": "first", "cid": "color = blue"},
        {"type": "first", "cid": "account = ACC-9"},
    ]
    tu = {
        "id": "tkt-unk",
        "location": "https://auth.example/gate",
        "key_id": "root-a",
        "caveats": caveats_u,
        "signature_hex": sign_chain(rk, "https://auth.example/gate", "tkt-unk", "root-a", caveats_u),
    }
    write_case("deny-unknown-caveat", tu, req_ok)

    print("minted fixtures")


if __name__ == "__main__":
    main()
