# go-passwordless — Implementation Plan

## 1. Goal

An agentless, read-only CLI that audits a small-business environment and answers:
"How can this org go passwordless, what blocks it, and what does staying on
passwords cost?" Output is an exportable Passwordless Readiness Report
(JSON + Markdown) that points at `open-passkey` for implementation and
`lockeidentity.com` for the commercial funnel.

Prior decisions (from user): MVP covers **AD + Entra**, ships as a **CLI binary**,
reports stay **fully local by default**.

## 2. Non-goals for MVP

- No installed agent, service, or daemon. Single ephemeral binary.
- No password, hash, or secret collection of any kind.
- No per-SaaS credential scraping. SaaS inventory comes from the IdP app list.
- No auto-remediation (no policy writes, no user provisioning).
- No MSP workspace, no hosted web assessment, no data upload.

## 3. Architecture

```
cmd/go-passwordless/main.go        CLI entry (assess/scan/report commands)
internal/model/                    Normalized inventory (source-agnostic)
internal/connector/ad/             Ephemeral LDAPS read-only scanner
internal/connector/entra/          Microsoft Graph read-only scanner
internal/assess/                   Readiness engine (blockers, classification)
internal/cost/                     Cost math from user inputs ONLY
internal/plan/                     Phased migration plan generator
internal/report/                   JSON + Markdown renderers
assessments/default.yaml           Question/fallback set for `unknown` gaps
```

`assess`, `cost`, and `plan` operate ONLY on `model.Inventory`. Connectors
translate AD/Entra facts into that model. This keeps the engine testable
without a live directory.

## 4. CLI UX (MVP)

```bash
# Zero-thinking entry point: interactive wizard detects environment,
# explains each step in plain language, validates as it goes.
go-passwordless start

# Active Directory: run from any DC-adjacent box, read-only bind, exit
go-passwordless scan ad \
  --dc ldaps://dc01.corp.example.com \
  --base-dn "DC=corp,DC=example,DC=com" \
  --bind-user "READONLYsvc@corp.example.com" \
  --out inventory-ad.json

# Entra: delegated OAuth device-code flow, read-only scopes, token never stored
go-passwordless scan entra \
  --tenant contoso.onmicrosoft.com \
  --out inventory-entra.json

# Merge + assess + report (fully offline after scan)
go-passwordless assess \
  --inventory inventory-ad.json,inventory-entra.json \
  --org org.yaml \
  --out report.json --format md
```

`org.yaml` holds ONLY user-supplied economics (headcount, helpdesk cost per
reset, resets/month, self-stated breach cost). No defaults are presented as
facts; missing values render as "not provided" rather than invented stats.

## 5. Normalized model (`internal/model`)

```go
type Inventory struct {
  Users   []User   // id, upn, enabled, authMethodsSeen, flags
  Devices []Device // id, os, joinType, compliant, confidence
  Apps    []App    // id, name, ssoProtocol, source
  Policy  Policy   // password, lockout, mfa/phishing-resistant allowed
}
type UserClass   int // ReadyNow, NeedsRemediation, Exception, Unknown
type Confidence  int // Observed, Inferred, Unknown
```

Every field carries provenance (`ad:`, `entra:`, `user:`) and confidence.
Anything not observed is `Unknown` and falls back to one targeted question —
never a full questionnaire.

## 6. AD connector (`internal/connector/ad`)

- Transport: LDAPS only. Refuse plaintext LDAP unless `--insecure-plain-ldap`
  with explicit warning (never default).
- Auth: NO new service user to create. The wizard prompts for the operator's
  OWN domain login (UPN + password, memory-only, LDAPS) and binds as them —
  every authenticated domain user can already read the allowlisted attributes.
  No NTLM relay, no hash extraction, no `unicodePwd`/`dBCSPwd` reads. If run
  on a domain-joined host, prefer the current logon context where possible so
  no password is typed at all.
- Library: `github.com/go-ldap/ldap/v3`, paged search, size/time limits.
- Attributes (allowlist only):
  - Identity: `sAMAccountName`, `userPrincipalName`, `memberOf`, `accountExpires`
  - Flags: `userAccountControl` (parse `SMARTCARD_REQUIRED`, `PASSWD_NOTREQD`,
    `DONT_EXPIRE_PASSWORD`, `ACCOUNTDISABLE`, `TRUSTED_FOR_DELEGATION`)
  - Hygiene: `pwdLastSet`, `msDS-UserPasswordExpiryTime`, `lockoutTime`
  - Service/shared heuristic: `servicePrincipalName` presence, `svc-*/service`
    naming, interactive-logon profile + stale password age
  - Devices: `operatingSystem`, `operatingSystemVersion` (WHfB/TPM-capable cut)
  - Policy: password-policy object (`maxPwdAge`, `minPwdLength`,
    `lockoutThreshold`), Hello-for-Business / smartcard GPO presence
- Reuse query patterns from `../directory-connector/internal/ldap`.

## 7. Entra connector (`internal/connector/entra`)

- Auth: NO service user and nothing for the customer to pre-create. The wizard
  drives a delegated device-code flow against a Locke multi-tenant app
  registration: the admin signs in as themselves, sees one consent screen
  (read-only scopes below), clicks Accept. No client secrets, no account
  provisioning on their side.
  Least-privilege read-only scopes:
  `User.Read.All`, `Policy.Read.All`,
  `DeviceManagementManagedDevices.Read.All`, `AuditLog.Read.All`.
- Endpoints (Microsoft Graph v1.0):
  - `authenticationMethodsPolicy` — is FIDO2 / WHfB / phone-sign-in allowed?
  - `conditionalAccess` policies — what is enforced vs. report-only?
  - per-user `authenticationMethods` — who already has phishing-resistant auth
  - `servicePrincipals` — enterprise-app (SaaS) inventory with SSO protocol
  - `devices` — join type, compliance, OS (feeds device readiness)
- Token is held in memory for the scan only, never written to disk.

## 8. Assessment engine (`internal/assess`)

Classification per user/app/device:

| Class | Meaning |
|---|---|
| `ReadyNow` | Policy allows + device/app supports phishing-resistant auth |
| `NeedsRemediation` | Fixable blocker (enable FIDO2 policy, upgrade OS, move app to SSO) |
| `Exception` | Shared/service account or app with no passwordless path — scoped compensating control |
| `Unknown` | Connector could not observe — one fallback question max |

Blocker taxonomy: `idp-policy`, `app-sso`, `device-capability`,
`recovery-path`, `shared-account`. Each finding cites the exact source
attribute or API object that produced it.

## 9. Cost model (`internal/cost`)

Transparent, input-driven only:

```
annual_reset_cost = resets_per_month * 12 * minutes_per_reset/60 * hourly_rate
```

Breach exposure renders ONLY from user-supplied incident cost, labeled as
"customer estimate, not Locke data." No third-party breach statistics in MVP.

## 10. Report (`internal/report`)

- `report.json`: canonical schema (versioned, e.g. `report/v1`), includes
  inventory summary, classifications, blockers, plan phases, cost inputs +
  outputs, provenance per finding.
- `report.md`: human-readable rendering for MSP handoff and GitHub/SEO.
- Footer on every report: "Ready to implement? → `open-passkey`
  (github.com/locke-inc/open-passkey) for drop-in WebAuthn/passkeys, or
  lockeidentity.com for managed rollout." Go snippet for `server-go`
  included in the `ReadyNow` section.

## 11. Security and privacy (MVP guarantees)

1. Read-only: no write scopes, no GPO/policy mutation, no provisioning.
2. Local-only: inventories and reports stay on disk; no telemetry, no upload.
3. Least data: LDAP attribute allowlist + Graph least-privilege scopes.
4. Ephemeral secrets: bind password via env var / prompt (never CLI history or
   file); OAuth token in memory only.
5. Auditable: `--dry-run` prints which queries would run; every finding links
   to its source.

## 12. Testing

- `internal/model`, `assess`, `cost`, `plan`: pure-Go unit tests with golden
  `testdata/*.json` inventories (no live infra).
- Connector tests: `ldapsearch`-style fake LDAP server + recorded Graph
  fixtures; live-integration tests gated behind env vars, never in CI default.
- CI: `go vet`, `gofmt -l`, `go test ./...`.

## 13. MVP milestones

1. **M0 skeleton**: `go.mod`, CLI plumbing, `model` types, JSON I/O. (~1 day)
2. **M1 AD scan**: LDAPS connector + `scan ad` emitting `Inventory`. (~2–3 days)
3. **M2 Entra scan**: Graph connector + `scan entra`. (~2–3 days)
4. **M3 engine + report**: classify, cost, plan, Markdown renderer + README
   targeting "go passwordless" keywords with open-passkey/Locke links. (~2 days)
5. **M4 dogfood**: run against a test AD + test Entra tenant, fix gaps, tag
   `v0.1.0`.

## 14. Assumptions — review checklist

- [ ] Module path will be `github.com/locke-inc/go-passwordless`.
- [ ] MVP connectors are AD (LDAPS) + Entra (Graph) only; Google Workspace and
      generic Okta/LDAP deferred past v0.1.0.
- [ ] CLI-only MVP; Go library reuse is incidental (internal packages), no
      stable public API promised.
- [ ] Fully local by default; no report upload, no telemetry, opt-in sharing
      deferred.
- [ ] AD scan requires customer/MSP to supply a read-only domain user + LDAPS
      reachability; no plaintext LDAP by default.
- [ ] Entra scan uses delegated device-code flow via a Locke multi-tenant app
      registration that we must create and publish.
- [ ] SaaS readiness is inferred from IdP app SSO protocol, not per-app probing.
- [ ] Devices without MDM/Intune get `Unknown`/inferred confidence, not a hard
      verdict.
- [ ] Cost section uses only customer-supplied numbers; we ship no default
      breach-cost statistics.
- [ ] Reuse LDAP patterns from `../directory-connector`; no shared code import
      in MVP (copy the query shapes, deduplicate later).
- [ ] Report footer links to `open-passkey` and `lockeidentity.com` — confirm
      exact URLs and Go snippet to embed.
- [ ] License: same as `open-passkey` (confirm which license before publish).
