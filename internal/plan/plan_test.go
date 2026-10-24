package plan

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/evaluate"
	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
	"github.com/yukiigarashi-dev/kodis/internal/policy"
)

const tenantID = "tenant-contoso.example.test"

var breakGlass = []string{"user-breakglass-01", "user-breakglass-02"}

func input(t *testing.T, scenario string) Input {
	t.Helper()
	f, err := mockentra.LoadFixture(filepath.Join("..", "..", "testdata", "scenarios", scenario, "tenant.json"))
	if err != nil {
		t.Fatal(err)
	}
	return inputFor(t, f.Snapshot())
}

func inputFor(t *testing.T, s model.Snapshot) Input {
	t.Helper()
	fs, err := evaluate.Evaluate(evaluate.Config{BreakGlassUserIDs: breakGlass}, s)
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		PlanID:    "plan-0001",
		TenantID:  tenantID,
		CreatedAt: time.Date(2026, 10, 25, 9, 0, 0, 0, time.FixedZone("JST", 9*3600)),
		Snapshot:  s,
		Findings:  fs,
	}
}

func TestBaselinePlanIsAllowedByPolicy(t *testing.T) {
	in := input(t, "baseline")
	res, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	p := res.Plan
	if len(p.Actions) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("got %d actions, %d skipped", len(p.Actions), len(res.Skipped))
	}
	a := p.Actions[0]
	if a.Target.ID != "ca-require-mfa-admins" || a.ExpectedVersion != "v7" ||
		a.ExpectedState != string(model.CAStateDisabled) || a.DesiredState != string(model.CAStateReportOnly) {
		t.Fatalf("unexpected action %+v", a)
	}
	if !p.CreatedAt.Equal(in.CreatedAt) || p.CreatedAt.Location() != time.UTC {
		t.Fatalf("createdAt %v not normalized to UTC", p.CreatedAt)
	}
	d := policy.Evaluate(policy.Config{TenantID: tenantID, BreakGlassUserIDs: breakGlass}, p, in.Snapshot)
	if !d.Allowed() {
		t.Fatalf("policy denied generated plan: %+v %+v", d.Reasons, d.Actions)
	}
}

func TestBreakGlassTargetIsSkipped(t *testing.T) {
	res, err := Build(input(t, "breakglass-not-excluded"))
	if !errors.Is(err, ErrNoActions) {
		t.Fatalf("got %v, want ErrNoActions", err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("skipped %+v, want 1", res.Skipped)
	}
}

func multiSnapshot() model.Snapshot {
	mk := func(id, ver string, excl []string) model.ConditionalAccessPolicy {
		return model.ConditionalAccessPolicy{
			ID: id, Version: ver, State: model.CAStateDisabled,
			IncludeRoles: []string{"role-global-admin"}, ExcludeUsers: excl, GrantControls: []string{model.GrantMFA},
		}
	}
	return model.Snapshot{TenantID: tenantID, Policies: []model.ConditionalAccessPolicy{
		mk("ca-c", "v3", breakGlass),
		mk("ca-a", "v1", breakGlass),
		mk("ca-b", "v2", nil), // missing break-glass exclusion
	}}
}

func TestMultipleTargets(t *testing.T) {
	in := inputFor(t, multiSnapshot())
	res, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var targets []string
	for _, a := range res.Plan.Actions {
		targets = append(targets, a.Target.ID+"@"+a.ExpectedVersion)
	}
	slices.Sort(targets)
	if !slices.Equal(targets, []string{"ca-a@v1", "ca-c@v3"}) {
		t.Fatalf("targets %v", targets)
	}
	if len(res.Skipped) != 1 || len(res.Plan.FindingIDs) != 2 {
		t.Fatalf("skipped %+v, findingIds %v", res.Skipped, res.Plan.FindingIDs)
	}
	d := policy.Evaluate(policy.Config{TenantID: tenantID, BreakGlassUserIDs: breakGlass}, res.Plan, in.Snapshot)
	if !d.Allowed() {
		t.Fatalf("policy denied generated plan: %+v", d.Actions)
	}
}

func TestDeterministic(t *testing.T) {
	in := inputFor(t, multiSnapshot())
	a, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(in.Findings)
	slices.Reverse(in.Snapshot.Policies)
	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	ha, err := model.HashPlan(a.Plan)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := model.HashPlan(b.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatal("plan depends on input order")
	}
}

func TestDoesNotMutateFindings(t *testing.T) {
	in := inputFor(t, multiSnapshot())
	// Evaluate returns sorted findings; reverse them so an in-place sort
	// inside Build would be observable.
	slices.Reverse(in.Findings)
	before := slices.Clone(in.Findings)
	if _, err := Build(in); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before, in.Findings) {
		t.Fatal("Build reordered or mutated caller's findings")
	}
}

func TestRejectsInconsistentInput(t *testing.T) {
	cases := map[string]func(*Input){
		"zero createdAt":  func(in *Input) { in.CreatedAt = time.Time{} },
		"empty plan id":   func(in *Input) { in.PlanID = "" },
		"tenant mismatch": func(in *Input) { in.TenantID = "tenant-other.example.test" },
		"invalid snapshot": func(in *Input) {
			in.Snapshot.Policies = append(in.Snapshot.Policies, in.Snapshot.Policies[0])
		},
		"target missing from snapshot": func(in *Input) {
			in.Snapshot.Policies = slices.DeleteFunc(slices.Clone(in.Snapshot.Policies), func(p model.ConditionalAccessPolicy) bool {
				return p.ID == "ca-require-mfa-admins"
			})
		},
		"target no longer disabled": func(in *Input) {
			ps := slices.Clone(in.Snapshot.Policies)
			ps[0].State = model.CAStateEnabled
			in.Snapshot.Policies = ps
		},
		"duplicate finding": func(in *Input) { in.Findings = append(in.Findings, in.Findings[0]) },
		"same id different content": func(in *Input) {
			// Without the duplicate check this would silently mark the
			// target unsafe and return ErrNoActions instead of an error.
			f := in.Findings[0]
			f.RuleID = evaluate.RuleBreakGlassNotExcluded
			in.Findings = append(in.Findings, f)
		},
		"invalid finding": func(in *Input) { in.Findings[0].Summary = "" },
		"finding wrong kind": func(in *Input) {
			in.Findings[0].Resource.Kind = "user"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := input(t, "baseline")
			mutate(&in)
			_, err := Build(in)
			if err == nil || errors.Is(err, ErrNoActions) {
				t.Fatalf("got %v, want an input error", err)
			}
		})
	}
}

func TestNoFindings(t *testing.T) {
	in := input(t, "baseline")
	in.Findings = nil
	if _, err := Build(in); !errors.Is(err, ErrNoActions) {
		t.Fatalf("got %v", err)
	}
}

func TestOtherRulesAreIgnored(t *testing.T) {
	in := input(t, "baseline")
	in.Findings = append(in.Findings, model.Finding{
		ID: "finding-other", RuleID: "some.future-rule", Severity: model.SeverityLow,
		Resource: model.ResourceRef{Kind: model.KindConditionalAccessPolicy, ID: "ca-block-legacy-auth"}, Summary: "x",
	})
	res, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Plan.Actions) != 1 || slices.Contains(res.Plan.FindingIDs, "finding-other") {
		t.Fatalf("unknown rule produced an action: %+v", res.Plan)
	}
}
