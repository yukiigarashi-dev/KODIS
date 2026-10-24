// Package plan proposes remediation plans from findings.
//
// Its output is an untrusted proposal, exactly like a plan from any other
// source (including a future LLM): it is only acted on after
// internal/policy allows it and a human approves its hash. The rules here
// avoid proposing obviously unsafe changes, but they are not a safety
// boundary.
package plan

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/evaluate"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// ErrNoActions means no finding led to a proposed action.
var ErrNoActions = errors.New("plan: no actionable findings")

// Input is everything Build needs. CreatedAt is injected so output is
// deterministic.
type Input struct {
	PlanID    string
	TenantID  string
	CreatedAt time.Time
	Snapshot  model.Snapshot
	Findings  []model.Finding
}

// Skip records an actionable finding that was deliberately not acted on.
type Skip struct {
	FindingID string
	Reason    string
}

// Result is a proposed plan plus the findings it chose not to act on.
type Result struct {
	Plan    model.Plan
	Skipped []Skip
}

// Build proposes one report-only action per ca.mfa-policy-disabled
// finding, skipping targets that also have a break-glass finding.
// Inconsistent input (unknown targets, state that contradicts a finding,
// duplicate findings) is an error rather than something to skip.
func Build(in Input) (Result, error) {
	if in.CreatedAt.IsZero() {
		return Result{}, fmt.Errorf("plan: createdAt is not set")
	}
	if err := in.Snapshot.Validate(); err != nil {
		return Result{}, fmt.Errorf("plan: invalid snapshot: %w", err)
	}
	if in.Snapshot.TenantID != in.TenantID {
		return Result{}, fmt.Errorf("plan: snapshot is for tenant %q, expected %q", in.Snapshot.TenantID, in.TenantID)
	}

	findings := slices.Clone(in.Findings)
	slices.SortFunc(findings, func(a, b model.Finding) int { return strings.Compare(a.ID, b.ID) })
	unsafe := map[model.ResourceRef]bool{}
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			return Result{}, fmt.Errorf("plan: invalid finding %q: %w", f.ID, err)
		}
		if i > 0 && findings[i-1].ID == f.ID {
			return Result{}, fmt.Errorf("plan: duplicate finding %q", f.ID)
		}
		if f.RuleID == evaluate.RuleBreakGlassNotExcluded {
			unsafe[f.Resource] = true
		}
	}

	var res Result
	var used []string
	for _, f := range findings {
		if f.RuleID != evaluate.RuleMFAPolicyDisabled {
			continue
		}
		if f.Resource.Kind != model.KindConditionalAccessPolicy {
			return Result{}, fmt.Errorf("plan: finding %q targets %q, want %q", f.ID, f.Resource.Kind, model.KindConditionalAccessPolicy)
		}
		cur, ok := in.Snapshot.Policy(f.Resource.ID)
		if !ok {
			return Result{}, fmt.Errorf("plan: finding %q targets policy %q not in snapshot", f.ID, f.Resource.ID)
		}
		if cur.State != model.CAStateDisabled {
			return Result{}, fmt.Errorf("plan: finding %q says %q is disabled, snapshot says %q", f.ID, cur.ID, cur.State)
		}
		if unsafe[f.Resource] {
			res.Skipped = append(res.Skipped, Skip{FindingID: f.ID, Reason: "break-glass accounts are not excluded from the target policy"})
			continue
		}
		used = append(used, f.ID)
		res.Plan.Actions = append(res.Plan.Actions, model.Action{
			ID:              fmt.Sprintf("action-%04d", len(res.Plan.Actions)+1),
			Operation:       model.OpSetConditionalAccessState,
			Target:          f.Resource,
			ExpectedVersion: cur.Version,
			ExpectedState:   string(model.CAStateDisabled),
			DesiredState:    string(model.CAStateReportOnly),
		})
	}
	if len(res.Plan.Actions) == 0 {
		return res, ErrNoActions
	}

	res.Plan.Schema = model.PlanSchemaV1
	res.Plan.ID = in.PlanID
	res.Plan.TenantID = in.TenantID
	res.Plan.CreatedAt = in.CreatedAt.UTC()
	res.Plan.FindingIDs = used
	if err := res.Plan.Validate(); err != nil {
		return Result{}, fmt.Errorf("plan: built invalid plan: %w", err)
	}
	return res, nil
}
