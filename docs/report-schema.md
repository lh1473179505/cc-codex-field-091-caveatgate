# report schema

```json
{
  "decision": "allow" | "deny",
  "reason_codes": ["..."],
  "ticket_id": "tkt-1",
  "key_id": "root-a",
  "caveat_count": 2,
  "discharge_used": 1,
  "notes": ["optional free-form notes"]
}
```

- `decision` is required.
- `reason_codes` is always an array (empty on allow).
- `discharge_used` counts discharges that satisfied third-party caveats.
