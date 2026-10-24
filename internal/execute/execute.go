// Package execute applies an approved plan. It is the only package that
// may hold an entra.Writer.
//
// The executor trusts nothing it is handed. Before any write it verifies
// the approval signature, plan hash and validity window, checks every
// action against its own built-in allowlist, re-reads tenant state and
// re-runs the policy engine on it, and claims the plan in a single-use
// ledger. Each write is a compare-and-swap on the version observed at
// planning time, so any change to the target since then (which always
// issues a new version) makes the write fail instead of applying.
//
// A successful write return is not proof of the change; internal/verify
// re-reads state independently.
package execute

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/approve"
	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
	"github.com/yukiigarashi-dev/kodis/internal/policy"
)

// Status is the overall outcome. Only StatusCompleted means every action
// was written; the zero value means nothing is known to have happened.
type Status string

const (
	// StatusDenied: a pre-write check failed; nothing was written.
	StatusDenied Status = "denied"
	// StatusFailed: the first write failed; nothing was written.
	StatusFailed Status = "failed"
	// StatusPartial: some actions were written, then one failed.
	StatusPartial Status = "partial"
	// StatusCompleted: every action's write returned success.
	StatusCompleted Status = "completed"
)

// StepStatus is the outcome of one action.
type StepStatus string

const (
	StepWritten    StepStatus = "written"
	StepFailed     StepStatus = "failed"
	StepNotStarted StepStatus = "not_started"
)

// Step records one action's outcome. NewVersion is what the writer
// claimed; it is evidence, not proof.
type Step struct {
	ActionID   string     `json:"actionId"`
	Status     StepStatus `json:"status"`
	NewVersion string     `json:"newVersion"`
	Err        string     `json:"error"`
}

// Result is the outcome of Execute.
type Result struct {
	PlanHash model.Digest `json:"planHash"`
	Status   Status       `json:"status"`
	// Reasons explain a denial.
	Reasons []string `json:"reasons"`
	Steps   []Step   `json:"steps"`
}

// ErrAlreadyClaimed means the plan was already executed (or attempted).
var ErrAlreadyClaimed = errors.New("execute: plan already claimed")

// Ledger records which plans have been claimed for execution. Claim must
// be atomic: of concurrent claims for the same hash, exactly one succeeds.
// It must also refuse approvals issued before the ledger's own start
// (its last init or recovery), checked under the same lock as the claim:
// claims made under earlier approvals may be missing from the ledger.
type Ledger interface {
	Claim(planHash model.Digest, approvalIssuedAt time.Time) error
}

// ErrApprovalPredatesLedger means the approval is older than the ledger.
var ErrApprovalPredatesLedger = errors.New("execute: approval predates the ledger")

// MemoryLedger is an in-process Ledger. It does not survive restarts.
// NotBefore is the ledger's start; it must be set.
type MemoryLedger struct {
	NotBefore time.Time

	mu   sync.Mutex
	seen map[model.Digest]bool
}

// Claim implements Ledger.
func (l *MemoryLedger) Claim(h model.Digest, approvalIssuedAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.NotBefore.IsZero() || approvalIssuedAt.IsZero() || approvalIssuedAt.Before(l.NotBefore) {
		return fmt.Errorf("%w: issued at %s, ledger started %s", ErrApprovalPredatesLedger, approvalIssuedAt.UTC(), l.NotBefore.UTC())
	}
	if l.seen == nil {
		l.seen = map[model.Digest]bool{}
	}
	if l.seen[h] {
		return ErrAlreadyClaimed
	}
	l.seen[h] = true
	return nil
}

// Config wires the executor's dependencies. All fields are required.
type Config struct {
	Policy   policy.Config
	Verifier *approve.Verifier
	Reader   entra.Reader
	Writer   entra.Writer
	Ledger   Ledger
	Now      func() time.Time
}

// Executor applies approved plans.
type Executor struct {
	cfg Config
}

// New validates the configuration.
func New(cfg Config) (*Executor, error) {
	switch {
	case cfg.Verifier == nil:
		return nil, errors.New("execute: verifier is required")
	case cfg.Reader == nil:
		return nil, errors.New("execute: reader is required")
	case cfg.Writer == nil:
		return nil, errors.New("execute: writer is required")
	case cfg.Ledger == nil:
		return nil, errors.New("execute: ledger is required")
	case cfg.Now == nil:
		return nil, errors.New("execute: clock is required")
	}
	return &Executor{cfg: cfg}, nil
}

type transition struct {
	op       model.Operation
	kind     model.ResourceKind
	from, to string
}

// builtin is the executor's own allowlist, kept separate from the policy
// engine's on purpose: a policy bug alone must not widen what can run.
var builtin = []transition{
	{model.OpSetConditionalAccessState, model.KindConditionalAccessPolicy, string(model.CAStateDisabled), string(model.CAStateReportOnly)},
}

func checkBuiltin(a model.Action) error {
	for _, t := range builtin {
		if a.Operation == t.op && a.Target.Kind == t.kind && a.ExpectedState == t.from && a.DesiredState == t.to {
			return nil
		}
	}
	return fmt.Errorf("action %s: %s on %s %s -> %s is not in the executor allowlist", a.ID, a.Operation, a.Target.Kind, a.ExpectedState, a.DesiredState)
}

func denied(r Result, format string, args ...any) Result {
	r.Status = StatusDenied
	r.Reasons = append(r.Reasons, fmt.Sprintf(format, args...))
	return r
}

// Execute runs every pre-write check and then writes the actions in order,
// stopping at the first failure. It never retries.
func (e *Executor) Execute(ctx context.Context, p model.Plan, a model.Approval) Result {
	var r Result
	h, err := model.HashPlan(p)
	if err != nil {
		return denied(r, "invalid plan: %v", err)
	}
	r.PlanHash = h

	if err := e.cfg.Verifier.Verify(a, p, e.cfg.Now()); err != nil {
		return denied(r, "approval: %v", err)
	}
	for _, act := range p.Actions {
		if err := checkBuiltin(act); err != nil {
			return denied(r, "%v", err)
		}
	}
	snap, err := e.cfg.Reader.ReadSnapshot(ctx)
	if err != nil {
		return denied(r, "re-read tenant state: %v", err)
	}
	d := policy.Evaluate(e.cfg.Policy, p, snap)
	if !d.Allowed() || d.PlanHash != h || a.Statement.PlanHash != h {
		r = denied(r, "policy denied plan on current state")
		for _, reason := range d.Reasons {
			r.Reasons = append(r.Reasons, fmt.Sprintf("%s: %s", reason.Code, reason.Detail))
		}
		for _, ad := range d.Actions {
			for _, reason := range ad.Reasons {
				r.Reasons = append(r.Reasons, fmt.Sprintf("%s: %s: %s", ad.ActionID, reason.Code, reason.Detail))
			}
		}
		return r
	}
	if err := e.cfg.Ledger.Claim(h, a.Statement.IssuedAt); err != nil {
		return denied(r, "ledger: %v", err)
	}

	for _, act := range p.Actions {
		r.Steps = append(r.Steps, Step{ActionID: act.ID, Status: StepNotStarted})
	}
	for i, act := range p.Actions {
		if err := e.beforeWrite(ctx, a); err != nil {
			r.Steps[i].Status = StepFailed
			r.Steps[i].Err = err.Error()
			r.Status = failedStatus(i)
			return r
		}
		v, err := e.cfg.Writer.SetConditionalAccessState(ctx, act.Target.ID, act.ExpectedVersion, model.CAState(act.DesiredState))
		if err != nil {
			r.Steps[i].Status = StepFailed
			r.Steps[i].Err = err.Error()
			r.Status = failedStatus(i)
			return r
		}
		r.Steps[i].Status = StepWritten
		r.Steps[i].NewVersion = v
	}
	r.Status = StatusCompleted
	return r
}

// beforeWrite stops a run whose context ended or whose approval expired
// while earlier actions were being written.
func (e *Executor) beforeWrite(ctx context.Context, a model.Approval) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if now := e.cfg.Now(); !now.Before(a.Statement.ExpiresAt) {
		return fmt.Errorf("approval expired at %s during execution", a.Statement.ExpiresAt)
	}
	return nil
}

func failedStatus(written int) Status {
	if written == 0 {
		return StatusFailed
	}
	return StatusPartial
}
