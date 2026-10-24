// Package policy decides whether a plan may be executed against an observed
// snapshot. It is pure: no I/O, no clock, no global state.
//
// The default is deny. A plan is allowed only if the configuration, plan
// and snapshot are all valid and every action passes every rule. The
// executor re-runs Evaluate on freshly read state immediately before
// writing; a Decision is never a capability by itself.
package policy

import (
	"fmt"
	"slices"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// ReasonCode identifies why something was denied.
type ReasonCode string

const (
	ReasonInvalidConfig         ReasonCode = "invalid_config"
	ReasonInvalidPlan           ReasonCode = "invalid_plan"
	ReasonInvalidSnapshot       ReasonCode = "invalid_snapshot"
	ReasonTenantMismatch        ReasonCode = "tenant_mismatch"
	ReasonOperationNotAllowed   ReasonCode = "operation_not_allowed"
	ReasonTransitionNotAllowed  ReasonCode = "transition_not_allowed"
	ReasonDuplicateTarget       ReasonCode = "duplicate_target"
	ReasonTargetNotFound        ReasonCode = "target_not_found"
	ReasonVersionMismatch       ReasonCode = "version_mismatch"
	ReasonStateMismatch         ReasonCode = "state_mismatch"
	ReasonBreakGlassNotExcluded ReasonCode = "break_glass_not_excluded"
	ReasonNoTargetScope         ReasonCode = "no_target_scope"
	ReasonGrantNotMFA           ReasonCode = "grant_not_mfa"
)

// Reason is one failed rule.
type Reason struct {
	Code   ReasonCode `json:"code"`
	Detail string     `json:"detail"`
}

// Config is operator-supplied policy configuration.
type Config struct {
	TenantID string
	// BreakGlassUserIDs must be excluded from every policy KODIS changes.
	// An empty list is invalid: without it no change is safe.
	BreakGlassUserIDs []string
}

type transition struct {
	from, to model.CAState
}

// allowed is the complete allowlist. Anything not listed is denied.
var allowed = map[model.Operation]map[model.ResourceKind][]transition{
	model.OpSetConditionalAccessState: {
		model.KindConditionalAccessPolicy: {{model.CAStateDisabled, model.CAStateReportOnly}},
	},
}

// ActionDecision is the outcome for one action.
type ActionDecision struct {
	ActionID string   `json:"actionId"`
	Reasons  []Reason `json:"reasons"`
}

// Allowed reports whether the action passed every rule.
func (a ActionDecision) Allowed() bool { return len(a.Reasons) == 0 }

// Decision is the outcome for a whole plan. The zero value denies.
type Decision struct {
	allowed bool
	// PlanHash is set only when the plan is valid.
	PlanHash model.Digest
	// Reasons are plan-level denials (config, plan, snapshot, tenant).
	Reasons []Reason
	Actions []ActionDecision
}

// Allowed reports whether the whole plan may proceed to approval.
func (d Decision) Allowed() bool { return d.allowed }

func deny(code ReasonCode, format string, args ...any) Reason {
	return Reason{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Evaluate decides a plan against a snapshot. All failing rules are
// reported, not only the first, so the audit log explains the denial.
func Evaluate(cfg Config, p model.Plan, snap model.Snapshot) Decision {
	var d Decision
	if err := validateConfig(cfg); err != nil {
		d.Reasons = append(d.Reasons, deny(ReasonInvalidConfig, "%v", err))
	}
	h, err := model.HashPlan(p)
	if err != nil {
		d.Reasons = append(d.Reasons, deny(ReasonInvalidPlan, "%v", err))
	} else {
		d.PlanHash = h
	}
	if err := snap.Validate(); err != nil {
		d.Reasons = append(d.Reasons, deny(ReasonInvalidSnapshot, "%v", err))
	}
	if len(d.Reasons) > 0 {
		return d
	}
	if p.TenantID != cfg.TenantID || snap.TenantID != cfg.TenantID {
		d.Reasons = append(d.Reasons, deny(ReasonTenantMismatch, "config %q, plan %q, snapshot %q", cfg.TenantID, p.TenantID, snap.TenantID))
		return d
	}

	targets := map[model.ResourceRef]int{}
	for _, a := range p.Actions {
		targets[a.Target]++
	}
	all := true
	for _, a := range p.Actions {
		ad := ActionDecision{ActionID: a.ID, Reasons: evaluateAction(cfg, a, snap)}
		if targets[a.Target] > 1 {
			ad.Reasons = append(ad.Reasons, deny(ReasonDuplicateTarget, "%s/%s is targeted by %d actions", a.Target.Kind, a.Target.ID, targets[a.Target]))
		}
		all = all && ad.Allowed()
		d.Actions = append(d.Actions, ad)
	}
	d.allowed = all && len(d.Actions) > 0
	return d
}

func validateConfig(cfg Config) error {
	if cfg.TenantID == "" {
		return fmt.Errorf("tenant id is empty")
	}
	if len(cfg.BreakGlassUserIDs) == 0 {
		return fmt.Errorf("no break-glass accounts configured")
	}
	for i, id := range cfg.BreakGlassUserIDs {
		if id == "" || id == model.AllUsers {
			return fmt.Errorf("breakGlassUserIDs[%d] %q is not a user id", i, id)
		}
	}
	return nil
}

func evaluateAction(cfg Config, a model.Action, snap model.Snapshot) []Reason {
	var rs []Reason
	kinds, ok := allowed[a.Operation]
	if !ok {
		return append(rs, deny(ReasonOperationNotAllowed, "operation %q", a.Operation))
	}
	trans, ok := kinds[a.Target.Kind]
	if !ok {
		return append(rs, deny(ReasonOperationNotAllowed, "operation %q on kind %q", a.Operation, a.Target.Kind))
	}
	want := transition{model.CAState(a.ExpectedState), model.CAState(a.DesiredState)}
	if !slices.Contains(trans, want) {
		rs = append(rs, deny(ReasonTransitionNotAllowed, "%s -> %s", a.ExpectedState, a.DesiredState))
	}

	cur, ok := snap.Policy(a.Target.ID)
	if !ok {
		return append(rs, deny(ReasonTargetNotFound, "policy %q", a.Target.ID))
	}
	if cur.Version != a.ExpectedVersion {
		rs = append(rs, deny(ReasonVersionMismatch, "observed %q, plan expects %q", cur.Version, a.ExpectedVersion))
	}
	if string(cur.State) != a.ExpectedState {
		rs = append(rs, deny(ReasonStateMismatch, "observed %q, plan expects %q", cur.State, a.ExpectedState))
	}
	for _, id := range cfg.BreakGlassUserIDs {
		if !slices.Contains(cur.ExcludeUsers, id) {
			rs = append(rs, deny(ReasonBreakGlassNotExcluded, "break-glass user %q is not excluded", id))
		}
	}
	if len(cur.IncludeUsers) == 0 && len(cur.IncludeRoles) == 0 {
		rs = append(rs, deny(ReasonNoTargetScope, "policy has no included users or roles"))
	}
	if !slices.Contains(cur.GrantControls, model.GrantMFA) || slices.Contains(cur.GrantControls, model.GrantBlock) {
		rs = append(rs, deny(ReasonGrantNotMFA, "grant controls %v must include %q and not %q", cur.GrantControls, model.GrantMFA, model.GrantBlock))
	}
	return rs
}
