# go-passwordless

Find out how your organization can **go passwordless**. An agentless, read-only
CLI that audits Active Directory and Entra ID, then produces an exportable
Passwordless Readiness Report: what is ready now, what needs remediation, and
which accounts are password-dependent exceptions.

- No agent to install. No service accounts to create. Nothing is changed.
- Reports stay on your machine. No passwords collected, ever.
- Ready to implement? Use [open-passkey](https://github.com/locke-inc/open-passkey)
  for drop-in WebAuthn/passkeys, or visit
  [lockeidentity.com](https://lockeidentity.com) for a managed rollout.

## Quick start

```bash
go build -o go-passwordless ./cmd/go-passwordless

# Guided (recommended — explains each step)
./go-passwordless start

# Or direct
./go-passwordless scan ad --dc ldaps://dc01.corp.example.com \
  --base-dn "DC=corp,DC=example,DC=com" --bind-user you@corp.example.com \
  --out inventory-ad.json

./go-passwordless scan entra --tenant contoso.onmicrosoft.com \
  --client-id $GO_PASSWORDLESS_ENTRA_CLIENT_ID \
  --out inventory-entra.json

./go-passwordless assess --inventory inventory-ad.json,inventory-entra.json \
  --org org.example.yaml --out report.json --format md,html
```

The HTML report is a single self-contained file carrying only the
go-passwordless identity — open it in a browser and use Print → Save as PDF
for an attractive, unbranded handoff.

Try it with zero infrastructure:

```bash
./go-passwordless assess --inventory testdata/sample-inventory.json \
  --org org.example.yaml --out /tmp/report.json --format md
```

## Layout

- `cmd/go-passwordless` — CLI (`start`, `scan`, `assess`)
- `internal/model` — normalized inventory (connectors translate, engine consumes)
- `internal/connector/ad` — LDAPS scanner (your own login, M1 for query engine)
- `internal/connector/entra` — Graph scanner (one admin-consent click, M2)
- `internal/assess`, `internal/cost`, `internal/plan`, `internal/report`
- `IMPLEMENTATION_PLAN.md` — full roadmap and assumptions checklist

And of course, it's written in Go :)

## Status

- M0 done: engine + report work end-to-end on sample data.
- M1 done: live AD LDAPS scan (`scan ad`) — operator's own login, read-only,
  WHfB signal via `msDS-KeyCredentialLink`.
- M2 done: live Entra Graph scan (`scan entra`) — one admin-consent click,
  delegated device-code flow, users + auth methods + apps + devices.
- Reports render as JSON, Markdown, and self-contained HTML (Save as PDF).
