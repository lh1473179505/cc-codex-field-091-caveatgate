# caveatgate

Offline lab for verifying HMAC capability tickets (macaroon-style) with
first-party caveats, third-party discharges, and request binding.

`python -m caveatgate inspect --ticket fixtures/cases/ok-basic/ticket.json`
prints the ticket id, location, and caveat summaries.

`python -m caveatgate verify` must evaluate a ticket (plus optional discharges)
against `docs/verify-rules.md` and write a JSON report. Exit 0 for allow, 1 for
deny, 2 for load failures.

```sh
python -m caveatgate verify \
  --ticket fixtures/cases/ok-basic/ticket.json \
  --request fixtures/cases/ok-basic/request.json \
  --keys fixtures/keys.json \
  --policy fixtures/policy.json \
  --report /tmp/caveatgate-report.json
```

Standard library only. No Docker, no network.
