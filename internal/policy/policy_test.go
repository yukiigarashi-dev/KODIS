package policy

import (
	"slices"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

const (
	tenant     = "tenant-contoso.example.test"
	breakGlass = "user-breakglass-01"
	policyID   = "ca-require-mfa-admins"
)

func cfg() Config {
	return Config{TenantID: tenant, BreakGlassUserIDs: []string{breakGlass}}
}

func caPolicy() model.ConditionalAccessPolicy {
	return model.ConditionalAccessPolicy{
		ID:            policyID,
		Version:       "v7",
		DisplayName:   "Require MFA for administrators",
		State:         model.CAStateDisabled,
		IncludeUsers:  []string{model.AllUsers},
		ExcludeUsers:  []string{breakGlass},
		IncludeRoles:  []string{"role-global-admin"},
		GrantControls: []string{model.GrantMFA},
	}
}

func snapshot() model.Snapshot {
	return model.Snapshot{TenantID: tenant, Policies: []model.ConditionalAccessPolicy{caPolicy()}}
}

func action() model.Action {
	return model.Action{
		ID:              "action-0001",
		Operation:       model.OpSetConditionalAccessState,
		Target:          model.ResourceRef{Kind: model.KindConditionalAccessPolicy, ID: policyID},
		ExpectedVersion: "v7",
		ExpectedState:   string(model.CAStateDisabled),
		DesiredState:    string(model.CAStateReportOnly),
	}
}

func plan() model.Plan {
	return model.Plan{
		Schema:     model.PlanSchemaV1,
		ID:         "plan-0001",
		TenantID:   tenant,
		CreatedAt:  time.Date(2026, 10, 24, 1, 2, 3, 0, time.UTC),
		FindingIDs: []string{"finding-0001"},
		Actions:    []model.Action{action()},
	}
}

func codes(d Decision) []ReasonCode {
	var out []ReasonCode
	for _, r := range d.Reasons {
		out = append(out, r.Code)
	}
	for _, a := range d.Actions {
		for _, r := range a.Reasons {
			out = append(out, r.Code)
		}
	}
	return out
}

func TestAllowsTheOnePermittedChange(t *testing.T) {
	d := Evaluate(cfg(), plan(), snapshot())
	if !d.Allowed() {
		t.Fatalf("expected allow, got %v", codes(d))
	}
	want, err := model.HashPlan(plan())
	if err != nil {
		t.Fatal(err)
	}
	if d.PlanHash != want {
		t.Fatal("decision not bound to plan hash")
	}
	if len(d.Actions) != 1 || !d.Actions[0].Allowed() {
		t.Fatalf("unexpected action decisions %+v", d.Actions)
	}
}

func TestZeroDecisionDenies(t *testing.T) {
	if (Decision{}).Allowed() {
		t.Fatal("zero Decision must deny")
	}
}

func TestDenies(t *testing.T) {
	type input struct {
		cfg  Config
		plan model.Plan
		snap model.Snapshot
	}
	cases := []struct {
		name   string
		mutate func(*input)
		want   ReasonCode
	}{
		// configuration
		{"empty config", func(in *input) { in.cfg = Config{} }, ReasonInvalidConfig},
		{"no break-glass", func(in *input) { in.cfg.BreakGlassUserIDs = nil }, ReasonInvalidConfig},
		{"empty break-glass id", func(in *input) { in.cfg.BreakGlassUserIDs = []string{""} }, ReasonInvalidConfig},
		{"break-glass is All", func(in *input) { in.cfg.BreakGlassUserIDs = []string{model.AllUsers} }, ReasonInvalidConfig},
		// plan / snapshot validity
		{"zero plan", func(in *input) { in.plan = model.Plan{} }, ReasonInvalidPlan},
		{"invalid plan", func(in *input) { in.plan.Actions[0].ID = "" }, ReasonInvalidPlan},
		{"zero snapshot", func(in *input) { in.snap = model.Snapshot{} }, ReasonInvalidSnapshot},
		{"duplicate policy in snapshot", func(in *input) { in.snap.Policies = append(in.snap.Policies, caPolicy()) }, ReasonInvalidSnapshot},
		{"unknown state in snapshot", func(in *input) { in.snap.Policies[0].State = "paused" }, ReasonInvalidSnapshot},
		// tenant binding
		{"plan for other tenant", func(in *input) { in.plan.TenantID = "tenant-other.example.test" }, ReasonTenantMismatch},
		{"snapshot of other tenant", func(in *input) { in.snap.TenantID = "tenant-other.example.test" }, ReasonTenantMismatch},
		{"config for other tenant", func(in *input) { in.cfg.TenantID = "tenant-other.example.test" }, ReasonTenantMismatch},
		// allowlist
		{"enable (enforce) policy", func(in *input) { in.plan.Actions[0].DesiredState = string(model.CAStateEnabled) }, ReasonTransitionNotAllowed},
		{"disable policy", func(in *input) {
			in.plan.Actions[0].ExpectedState = string(model.CAStateReportOnly)
			in.plan.Actions[0].DesiredState = string(model.CAStateDisabled)
			in.snap.Policies[0].State = model.CAStateReportOnly
		}, ReasonTransitionNotAllowed},
		{"enabled to report-only", func(in *input) {
			in.plan.Actions[0].ExpectedState = string(model.CAStateEnabled)
			in.snap.Policies[0].State = model.CAStateEnabled
		}, ReasonTransitionNotAllowed},
		{"unknown desired state", func(in *input) { in.plan.Actions[0].DesiredState = "off" }, ReasonTransitionNotAllowed},
		// observed state preconditions
		{"target missing", func(in *input) { in.snap.Policies = nil }, ReasonTargetNotFound},
		{"target id differs", func(in *input) { in.plan.Actions[0].Target.ID = "ca-other" }, ReasonTargetNotFound},
		{"version changed", func(in *input) { in.snap.Policies[0].Version = "v8" }, ReasonVersionMismatch},
		{"state already report-only", func(in *input) { in.snap.Policies[0].State = model.CAStateReportOnly }, ReasonStateMismatch},
		{"state already enabled", func(in *input) { in.snap.Policies[0].State = model.CAStateEnabled }, ReasonStateMismatch},
		{"break-glass not excluded", func(in *input) { in.snap.Policies[0].ExcludeUsers = nil }, ReasonBreakGlassNotExcluded},
		{"second break-glass not excluded", func(in *input) {
			in.cfg.BreakGlassUserIDs = append(in.cfg.BreakGlassUserIDs, "user-breakglass-02")
		}, ReasonBreakGlassNotExcluded},
		{"break-glass only included", func(in *input) {
			in.snap.Policies[0].ExcludeUsers = nil
			in.snap.Policies[0].IncludeUsers = []string{breakGlass}
		}, ReasonBreakGlassNotExcluded},
		{"no scope", func(in *input) {
			in.snap.Policies[0].IncludeUsers = nil
			in.snap.Policies[0].IncludeRoles = nil
		}, ReasonNoTargetScope},
		{"grant without mfa", func(in *input) { in.snap.Policies[0].GrantControls = []string{"compliantDevice"} }, ReasonGrantNotMFA},
		{"grant empty", func(in *input) { in.snap.Policies[0].GrantControls = nil }, ReasonGrantNotMFA},
		{"grant block", func(in *input) { in.snap.Policies[0].GrantControls = []string{model.GrantMFA, model.GrantBlock} }, ReasonGrantNotMFA},
		{"grant MFA wrong case", func(in *input) { in.snap.Policies[0].GrantControls = []string{"MFA"} }, ReasonGrantNotMFA},
		// whole-plan semantics
		{"same target twice", func(in *input) {
			a := action()
			a.ID = "action-0002"
			in.plan.Actions = append(in.plan.Actions, a)
		}, ReasonDuplicateTarget},
		{"one bad action denies all", func(in *input) {
			p := caPolicy()
			p.ID = "ca-second"
			p.ExcludeUsers = nil
			in.snap.Policies = append(in.snap.Policies, p)
			a := action()
			a.ID = "action-0002"
			a.Target.ID = "ca-second"
			in.plan.Actions = append(in.plan.Actions, a)
		}, ReasonBreakGlassNotExcluded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input{cfg(), plan(), snapshot()}
			c.mutate(&in)
			d := Evaluate(in.cfg, in.plan, in.snap)
			if d.Allowed() {
				t.Fatal("expected deny")
			}
			if got := codes(d); !slices.Contains(got, c.want) {
				t.Fatalf("reasons %v do not include %s", got, c.want)
			}
		})
	}
}

func TestUnknownOperationDeniedEvenIfModelAcceptsIt(t *testing.T) {
	// Simulate a future model operation that the policy allowlist does not
	// know about: Evaluate must deny it rather than fall through.
	a := action()
	a.Operation = "conditionalAccess.delete"
	got := evaluateAction(cfg(), a, snapshot())
	if len(got) == 0 || got[0].Code != ReasonOperationNotAllowed {
		t.Fatalf("got %v, want operation_not_allowed", got)
	}
	a = action()
	a.Target.Kind = "user"
	got = evaluateAction(cfg(), a, snapshot())
	if len(got) == 0 || got[0].Code != ReasonOperationNotAllowed {
		t.Fatalf("got %v, want operation_not_allowed", got)
	}
}

func TestReportsAllFailures(t *testing.T) {
	s := snapshot()
	s.Policies[0].Version = "v8"
	s.Policies[0].ExcludeUsers = nil
	s.Policies[0].GrantControls = nil
	got := codes(Evaluate(cfg(), plan(), s))
	for _, want := range []ReasonCode{ReasonVersionMismatch, ReasonBreakGlassNotExcluded, ReasonGrantNotMFA} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

func TestDoesNotMutateInputs(t *testing.T) {
	c, p, s := cfg(), plan(), snapshot()
	before, err := model.HashPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	Evaluate(c, p, s)
	after, err := model.HashPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if before != after || !slices.Equal(s.Policies[0].ExcludeUsers, []string{breakGlass}) || len(c.BreakGlassUserIDs) != 1 {
		t.Fatal("Evaluate mutated its inputs")
	}
}

// FuzzEvaluate checks Evaluate against an independent oracle: whenever it
// allows, every safety condition must hold when re-checked directly.
func FuzzEvaluate(f *testing.F) {
	f.Add("v7", "disabled", "enabledForReportingButNotEnforced", "v7", "disabled", breakGlass, "mfa", policyID, tenant)
	f.Add("v7", "enabled", "enabledForReportingButNotEnforced", "v7", "enabled", breakGlass, "mfa", policyID, tenant)
	f.Add("v7", "disabled", "enabled", "v8", "disabled", "", "block", "x", "t")
	f.Fuzz(func(t *testing.T, expVer, expState, desState, obsVer, obsState, excluded, grant, targetID, planTenant string) {
		p := plan()
		p.TenantID = planTenant
		p.Actions[0].ExpectedVersion = expVer
		p.Actions[0].ExpectedState = expState
		p.Actions[0].DesiredState = desState
		p.Actions[0].Target.ID = targetID
		s := snapshot()
		s.Policies[0].Version = obsVer
		s.Policies[0].State = model.CAState(obsState)
		s.Policies[0].ExcludeUsers = []string{excluded}
		s.Policies[0].GrantControls = []string{grant}

		d := Evaluate(cfg(), p, s)
		if !d.Allowed() {
			return
		}
		switch {
		case planTenant != tenant:
			t.Fatal("allowed plan for another tenant")
		case targetID != policyID:
			t.Fatal("allowed unknown target")
		case expState != "disabled" || desState != "enabledForReportingButNotEnforced":
			t.Fatalf("allowed transition %s -> %s", expState, desState)
		case obsVer != expVer:
			t.Fatal("allowed version mismatch")
		case obsState != expState:
			t.Fatal("allowed state mismatch")
		case excluded != breakGlass:
			t.Fatal("allowed without break-glass exclusion")
		case grant != "mfa":
			t.Fatalf("allowed grant %q", grant)
		}
		if h, err := model.HashPlan(p); err != nil || h != d.PlanHash {
			t.Fatal("allowed decision not bound to plan hash")
		}
	})
}
