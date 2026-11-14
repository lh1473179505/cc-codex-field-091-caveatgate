# caveatgate verify rules

This lab uses JSON stand-ins for macaroon-style capability tickets. Signatures
are HMAC-SHA256 over a fixed byte layout (see below). Do not invent a different
wire format.

## Objects

### Ticket

```json
{
  "id": "tkt-1",
  "location": "https://auth.example/gate",
  "key_id": "root-a",
  "caveats": [ /* ordered */ ],
  "signature_hex": "..."
}
```

### Caveat

First-party:

```json
{"type": "first", "cid": "time < 2026-04-02T00:00:00Z"}
```

or structured forms the verifier must accept equivalently:

```json
{"type": "first", "cid": "method = GET"}
{"type": "first", "cid": "path = /v1/orders"}
{"type": "first", "cid": "path_prefix = /v1/"}
{"type": "first", "cid": "account = ACC-9"}
```

Third-party:

```json
{
  "type": "third",
  "cid": "need-otp",
  "vid_hex": "<hex of ciphertext binding discharge root>",
  "location": "https://otp.example/discharge"
}
```

`vid_hex` is AES not required in this lab: it is `HMAC-SHA256(root_key, "vid|" + cid + "|" + discharge_key_id)` hex, and the discharge ticket must use `key_id` equal to that `discharge_key_id` embedded as UTF-8 after the last `|` in the preimage. For fixtures, `vid` metadata is also listed under `fixtures/keys.json` → `discharges` for cross-checks, but verification must recompute and must not trust a client-supplied discharge key id that fails the vid check.

### Discharge ticket

Same shape as a ticket. Its caveats are only first-party. Its signature chain
starts from the discharge root key identified by vid, not from the parent root.

### Request

```json
{
  "method": "GET",
  "path": "/v1/orders/42",
  "account": "ACC-9",
  "now": "2026-04-01T12:00:00Z"
}
```

`now` is the verifier clock for `time <` caveats (ISO-8601 UTC, second precision).

## Signature byte layout

For a ticket or discharge with ordered caveats `c0..cn-1`:

1. `msg0 = UTF-8(location) || 0x00 || UTF-8(id) || 0x00 || UTF-8(key_id)`
2. `sig0 = HMAC-SHA256(key, msg0)` where `key` is the raw root/discharge key bytes from `keys.json`.
3. For each caveat in order:
   - first: `msg = sig_{i} || 0x00 || UTF-8("first") || 0x00 || UTF-8(cid)`
   - third: `msg = sig_{i} || 0x00 || UTF-8("third") || 0x00 || UTF-8(cid) || 0x00 || UTF-8(location) || 0x00 || unhex(vid_hex)`
   - `sig_{i+1} = HMAC-SHA256(sig_i, msg)`  (HMAC key is the previous signature bytes, not the root key)

The stored `signature_hex` must equal `sig_n` after all caveats. Empty caveat list means `signature_hex == sig0` hex.

## Verification algorithm (normative)

1. Load keys/policy/ticket/request/(discharges). Fail load (exit 2) if JSON missing/invalid or required key_id absent.
2. Recompute the ticket signature chain with the root key for `ticket.key_id`. If mismatch → deny `bad_signature`.
3. Evaluate first-party caveats against the request (see semantics). Any failure → deny with the matching reason.
4. For each third-party caveat in ticket order:
   - Find exactly one unused discharge whose `location` equals the caveat location AND whose root key id satisfies the vid binding for this caveat.
   - Recompute that discharge signature chain; mismatch → `bad_discharge_signature`.
   - Evaluate the discharge's first-party caveats against the same request.
   - Bind discharge: compute `bound = HMAC-SHA256(discharge.signature_bytes, ticket.signature_bytes)` and require the discharge bundle entry to present `binding_hex` equal to `bound` hex. Missing/wrong → `unbound_discharge`.
5. Extra unused discharges are ignored (do not deny solely for extras).
6. Policy checks:
   - `max_caveats`: if ticket caveat count > max → `too_many_caveats`
   - `allowed_locations`: ticket.location must be listed
   - `require_account_caveat`: if true, ticket must include a first-party `account = ...` caveat
7. If all pass → allow.

## First-party caveat semantics

| cid form | rule |
|---|---|
| `time < <iso>` | `request.now` must be strictly before that instant |
| `method = <m>` | case-sensitive equality with `request.method` |
| `path = <p>` | exact equality with `request.path` |
| `path_prefix = <p>` | `request.path` starts with `p` (literal prefix, not regex) |
| `account = <a>` | exact equality with `request.account` |

Unknown first-party cid forms → deny `unknown_caveat` (do not skip).

## Reason codes

Use these exact strings in `reason_codes` (array, stable order of detection; stop at first hard failure group as implemented, but include all codes you actually detected before returning):

`bad_signature`, `bad_discharge_signature`, `unbound_discharge`, `missing_discharge`, `expired`, `method_mismatch`, `path_mismatch`, `prefix_mismatch`, `account_mismatch`, `unknown_caveat`, `too_many_caveats`, `location_denied`, `account_caveat_required`

Map `time <` failure to `expired`.

## Non-goals / forbidden shortcuts

- Do not treat `path_prefix` as substring search anywhere in the path.
- Do not accept a discharge that only matches `cid` text without vid key binding.
- Do not verify only the root `sig0` and ignore caveat chaining.
- Do not call network services or add non-stdlib dependencies.
