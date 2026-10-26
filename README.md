# KODIS

**Key-scoped Operations & Deterministic Inspection System** — a defensive security agent that lets organizations without dedicated security staff apply security improvements safely.

KODIS runs a fixed pipeline against a Microsoft Entra tenant:

**Inspect → Evaluate → Plan → Approve → Execute → Verify**

> **Status: MVP.** KODIS currently operates **only on a simulated tenant** loaded from a synthetic fixture. It contains no code that connects to a real tenant or the Microsoft Graph API, uses no real customer data, and has no LLM in the loop. Do not use it for production changes.

## What the MVP does

- **Inspect** reads Conditional Access policies from the (simulated) tenant through a read-only interface.
- **Evaluate** applies deterministic rules, e.g. "a policy that requires MFA is disabled" and "a policy does not exclude every break-glass account".
- **Plan** proposes changes. Exactly one change is allowed: moving a Conditional Access policy from `disabled` to report-only (`enabledForReportingButNotEnforced`), and never for a policy that does not exclude all break-glass accounts.
- **Approve** requires a human to type the first characters of the plan hash; the approval is an ed25519 signature bound to that exact plan, valid for at most one hour.
- **Execute** re-verifies everything before writing and writes with compare-and-swap on the version observed at planning time.
- **Verify** re-reads the tenant independently of the executor and checks the result.

Every decision, including denials, is recorded in a hash-chained audit log.

## Safety design

The rules below are enforced in code and by tests (see [CLAUDE.md](CLAUDE.md) for the full list of invariants):

- **Fail closed.** Unknown operations, missing or unknown fields, parse errors and expired approvals are all rejected.
- **Plans are untrusted.** A plan is only data; the policy engine (`internal/policy`) decides, and it has no I/O.
- **The executor trusts nothing it is handed.** `internal/execute` re-checks the approval signature, plan hash and validity, its own built-in allowlist, and the current tenant state, then writes with compare-and-swap.
- **Approvals are bound to one plan hash.** The hash covers the plan's canonical encoding, so any change to its content invalidates the approval.
- **Independent verification.** `internal/verify` never uses executor results; it reads the tenant again.
- **Single-use, auditable execution.** Each plan is claimed once in the audit log; the log is created explicitly, scoped to one tenant, and checked against an externally kept checkpoint on every run.
- **Package boundaries are tested.** `internal/archtest` fails the test suite if, for example, anything other than the executor calls a tenant write, or the policy engine imports I/O packages.
- **Go standard library only.** `go.mod` has no `require`; no npm or other dependencies.

## Requirements

- Go 1.27 or later
- Linux (or another Unix). Approver key files and audit log locking are refused on other platforms.
- For running the tests: a systemd user session (`systemd-run --user --scope`), see [Testing](#testing).

## Quick start

Build the CLI:

```sh
go build -o kodis ./cmd/kodis
```

Create an approver key pair (the private key is written with mode 0600 and never overwritten; without flags it goes to `~/.config/kodis/approver.key`):

```sh
./kodis keygen -key ./approver.key -pub ./approver.pub
```

Create an audit log for the tenant in the operator config. Logs are only ever created by this command:

```sh
./kodis audit-init -config testdata/scenarios/baseline/config.json -audit ./audit.jsonl
```

It prints a checkpoint such as `kodis-ckpt/v1:<log id>:1:<hash>`. **Keep it somewhere the audit log's writer cannot modify** (another account, append-only storage, paper). Every run requires the latest checkpoint and prints the next one.

Run the pipeline against the simulated baseline tenant:

```sh
./kodis run \
  -config testdata/scenarios/baseline/config.json \
  -fixture testdata/scenarios/baseline/tenant.json \
  -audit ./audit.jsonl \
  -checkpoint 'kodis-ckpt/v1:...' \
  -approver alice -key ./approver.key -pub ./approver.pub
```

KODIS shows the findings, the proposed plan and the policy decision, then asks you to type the first 12 hex characters of the plan hash. Anything else (including `y`) is treated as "not approved".

Check the audit log (read-only):

```sh
./kodis audit-verify -audit ./audit.jsonl -checkpoint 'kodis-ckpt/v1:...'
```

If you lose your checkpoint, `kodis audit-recover -audit PATH -reason TEXT` records an explicit recovery after a typed confirmation. Records before it are marked unverified, and every approval issued before the recovery is refused.

### Exit codes of `kodis run`

| Code | Meaning |
|---|---|
| 0 | Change applied and independently verified |
| 1 | Error (including a checkpoint mismatch or an unwritable audit log) |
| 2 | Usage error |
| 3 | Nothing to do |
| 4 | Denied by policy |
| 5 | Not approved |
| 6 | Execution did not complete |
| 7 | Verification failed |

## Testing

All tests, vet runs and mutation tests are run through a wrapper that puts them in a systemd user scope with memory, swap, CPU, task and time limits, so a runaway test cannot exhaust the host:

```sh
gofmt -l .                                         # must print nothing
scripts/safe-test.sh go vet ./...
scripts/safe-test.sh go test -race -count=1 ./...
```

The defaults are `MemoryMax=2G`, `MemorySwapMax=0`, `CPUQuota=200%`, `TasksMax=512` and a 300-second timeout. They can be lowered (for example `KODIS_MEM_MAX=1G KODIS_TIMEOUT=120`) but not raised or removed; invalid values are rejected before anything runs.

The repository expects an offline toolchain: `GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly`.

## Project layout

```
cmd/kodis            CLI: keygen, audit-init, run, audit-verify, audit-recover
internal/model       data types, strict JSON decoding, canonical plan hash
internal/inspect     read-only collection of tenant state
internal/evaluate    deterministic rules -> findings
internal/plan        findings -> proposed plan (untrusted output)
internal/policy      allow/deny decision, pure function
internal/approve     ed25519 approvals and key files
internal/execute     the only package allowed to write to the tenant
internal/verify      independent post-execution check
internal/audit       hash-chained audit log, checkpoints, single-use ledger
internal/entra       Reader/Writer interfaces (no real implementation)
internal/mockentra   in-memory simulated tenant with fault injection
internal/archtest    tests that enforce package boundaries and dependencies
testdata/scenarios   synthetic tenant fixtures and operator configs
scripts/safe-test.sh resource-limited test runner
docs/                design notes
```

## Known limitations

- **Approver and executor can be the same person.** Whoever holds the approver key can approve; with one operator this is not separation of duties.
- **Checkpoints do not cover records written after the last kept checkpoint.** Removing those records is not detected, and a plan whose claim was removed can be executed again under a new approval. The trust in a checkpoint is only as good as the independence of where it is kept. See [docs/audit-checkpoint.md](docs/audit-checkpoint.md) for the full list of residual risks.
- **Only the simulated tenant is supported.** The simulated tenant is rebuilt from its fixture on every run.
- **One allowed operation.** Only the Conditional Access report-only change described above.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
