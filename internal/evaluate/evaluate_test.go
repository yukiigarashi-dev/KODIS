package evaluate

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

var cfg = Config{BreakGlassUserIDs: []string{"user-breakglass-01", "user-breakglass-02"}}

func load(t *testing.T, scenario string) model.Snapshot {
	t.Helper()
	f, err := mockentra.LoadFixture(filepath.Join("..", "..", "testdata", "scenarios", scenario, "tenant.json"))
	if err != nil {
		t.Fatal(err)
	}
	return f.Snapshot()
}

type key struct{ rule, resource string }

func keys(fs []model.Finding) []key {
	var out []key
	for _, f := range fs {
		out = append(out, key{f.RuleID, f.Resource.ID})
	}
	slices.SortFunc(out, func(a, b key) int {
		return strings.Compare(a.rule+"/"+a.resource, b.rule+"/"+b.resource)
	})
	return out
}

func TestScenarios(t *testing.T) {
	cases := map[string][]key{
		"baseline": {
			{RuleMFAPolicyDisabled, "ca-require-mfa-admins"},
		},
		"breakglass-not-excluded": {
			{RuleBreakGlassNotExcluded, "ca-require-mfa-admins"},
			{RuleMFAPolicyDisabled, "ca-require-mfa-admins"},
		},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			fs, err := Evaluate(cfg, load(t, name))
			if err != nil {
				t.Fatal(err)
			}
			if got := keys(fs); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for _, f := range fs {
				if err := f.Validate(); err != nil {
					t.Errorf("invalid finding %+v: %v", f, err)
				}
			}
		})
	}
}

func policy() model.ConditionalAccessPolicy {
	return model.ConditionalAccessPolicy{
		ID:            "ca-1",
		Version:       "v1",
		State:         model.CAStateDisabled,
		IncludeRoles:  []string{"role-global-admin"},
		ExcludeUsers:  []string{"user-breakglass-01", "user-breakglass-02"},
		GrantControls: []string{model.GrantMFA},
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.ConditionalAccessPolicy)
		want   []string
	}{
		{"disabled mfa", func(*model.ConditionalAccessPolicy) {}, []string{RuleMFAPolicyDisabled}},
		{"enabled mfa", func(p *model.ConditionalAccessPolicy) { p.State = model.CAStateEnabled }, nil},
		{"report-only mfa", func(p *model.ConditionalAccessPolicy) { p.State = model.CAStateReportOnly }, nil},
		{"disabled non-mfa", func(p *model.ConditionalAccessPolicy) { p.GrantControls = []string{"compliantDevice"} }, nil},
		{"disabled mfa+block", func(p *model.ConditionalAccessPolicy) { p.GrantControls = []string{model.GrantMFA, model.GrantBlock} }, nil},
		{"disabled no grant", func(p *model.ConditionalAccessPolicy) { p.GrantControls = nil }, nil},
		{"enabled missing one break-glass", func(p *model.ConditionalAccessPolicy) {
			p.State = model.CAStateEnabled
			p.ExcludeUsers = []string{"user-breakglass-01"}
		}, []string{RuleBreakGlassNotExcluded}},
		{"report-only missing all break-glass", func(p *model.ConditionalAccessPolicy) {
			p.State = model.CAStateReportOnly
			p.ExcludeUsers = nil
		}, []string{RuleBreakGlassNotExcluded}},
		{"break-glass only included", func(p *model.ConditionalAccessPolicy) {
			p.State = model.CAStateEnabled
			p.ExcludeUsers = nil
			p.IncludeUsers = []string{"user-breakglass-01", "user-breakglass-02"}
		}, []string{RuleBreakGlassNotExcluded}},
		{"disabled mfa missing break-glass", func(p *model.ConditionalAccessPolicy) { p.ExcludeUsers = nil },
			[]string{RuleBreakGlassNotExcluded, RuleMFAPolicyDisabled}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := policy()
			c.mutate(&p)
			fs, err := Evaluate(cfg, model.Snapshot{TenantID: "tenant-a.example.test", Policies: []model.ConditionalAccessPolicy{p}})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range fs {
				got = append(got, f.RuleID)
			}
			slices.Sort(got)
			if !slices.Equal(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	s := load(t, "baseline")
	s.Policies[1].ExcludeUsers = nil // add a second finding
	a, err := Evaluate(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(s.Policies)
	b, err := Evaluate(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) < 2 || !slices.Equal(a, b) {
		t.Fatalf("output depends on snapshot order:\n%v\n%v", a, b)
	}
}

func TestFindingIDs(t *testing.T) {
	a := finding(RuleMFAPolicyDisabled, model.SeverityHigh, "ca-1", "x")
	if b := finding(RuleMFAPolicyDisabled, model.SeverityHigh, "ca-1", "different summary"); a.ID != b.ID {
		t.Fatal("finding ID must depend only on rule and resource")
	}
	if b := finding(RuleBreakGlassNotExcluded, model.SeverityHigh, "ca-1", "x"); a.ID == b.ID {
		t.Fatal("different rules collide")
	}
	if b := finding(RuleMFAPolicyDisabled, model.SeverityHigh, "ca-2", "x"); a.ID == b.ID {
		t.Fatal("different resources collide")
	}
}

func TestRejects(t *testing.T) {
	s := load(t, "baseline")
	for name, c := range map[string]Config{
		"no break-glass":     {},
		"empty break-glass":  {BreakGlassUserIDs: []string{""}},
		"All as break-glass": {BreakGlassUserIDs: []string{model.AllUsers}},
	} {
		if _, err := Evaluate(c, s); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	bad := s
	bad.Policies = append(slices.Clone(s.Policies), s.Policies[0])
	if _, err := Evaluate(cfg, bad); err == nil {
		t.Error("invalid snapshot accepted")
	}
}

func TestOversizedSummaryFailsClosed(t *testing.T) {
	var many []string
	for i := range 100 {
		many = append(many, "user-breakglass-"+strings.Repeat("x", 20)+string(rune('a'+i%26))+strings.Repeat("y", i%5))
	}
	p := policy()
	p.ExcludeUsers = nil
	_, err := Evaluate(Config{BreakGlassUserIDs: many}, model.Snapshot{TenantID: "tenant-a.example.test", Policies: []model.ConditionalAccessPolicy{p}})
	if err == nil {
		t.Fatal("a finding that fails validation must make Evaluate fail")
	}
}
