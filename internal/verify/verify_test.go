package verify

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

const (
	tenantID    = "tenant-contoso.example.test"
	adminPolicy = "ca-require-mfa-admins"
)

var cfg = Config{BreakGlassUserIDs: []string{"user-breakglass-01", "user-breakglass-02"}}

func setup(t *testing.T) *mockentra.Tenant {
	t.Helper()
	f, err := mockentra.LoadFixture(filepath.Join("..", "..", "testdata", "scenarios", "baseline", "tenant.json"))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := mockentra.New(f)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func plan() model.Plan {
	return model.Plan{
		Schema:     model.PlanSchemaV1,
		ID:         "plan-0001",
		TenantID:   tenantID,
		CreatedAt:  time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC),
		FindingIDs: []string{"finding-0001"},
		Actions: []model.Action{{
			ID:              "action-0001",
			Operation:       model.OpSetConditionalAccessState,
			Target:          model.ResourceRef{Kind: model.KindConditionalAccessPolicy, ID: adminPolicy},
			ExpectedVersion: "v7",
			ExpectedState:   string(model.CAStateDisabled),
			DesiredState:    string(model.CAStateReportOnly),
		}},
	}
}

// write applies the plan's change directly, standing in for the executor.
func write(t *testing.T, tn *mockentra.Tenant) {
	t.Helper()
	if _, err := tn.Writer().SetConditionalAccessState(context.Background(), adminPolicy, "v7", model.CAStateReportOnly); err != nil {
		t.Fatal(err)
	}
}

func TestVerified(t *testing.T) {
	tn := setup(t)
	write(t, tn)
	rep, err := Verify(context.Background(), tn.Reader(), cfg, plan())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Verified() || len(rep.Checks) != 1 || !rep.Checks[0].OK() {
		t.Fatalf("report %+v", rep)
	}
}

func TestZeroReportIsNotVerified(t *testing.T) {
	if (Report{}).Verified() {
		t.Fatal("zero Report must not be verified")
	}
}

func TestNotVerified(t *testing.T) {
	cases := []struct {
		name string
		prep func(t *testing.T, tn *mockentra.Tenant)
		want string
	}{
		{"nothing written", func(*testing.T, *mockentra.Tenant) {}, "state is"},
		{"write dropped", func(t *testing.T, tn *mockentra.Tenant) {
			tn.InjectFault(mockentra.FaultDropWrite)
			write(t, tn)
		}, "state is"},
		{"stale reader", func(t *testing.T, tn *mockentra.Tenant) {
			tn.InjectFault(mockentra.FaultStaleRead)
			write(t, tn)
		}, "no write is visible"},
		{"break-glass removed after write", func(t *testing.T, tn *mockentra.Tenant) {
			write(t, tn)
			if err := tn.Modify(adminPolicy, func(p *model.ConditionalAccessPolicy) { p.ExcludeUsers = p.ExcludeUsers[:1] }); err != nil {
				t.Fatal(err)
			}
		}, "user-breakglass-02"},
		{"someone else enforced it", func(t *testing.T, tn *mockentra.Tenant) {
			write(t, tn)
			if err := tn.Modify(adminPolicy, func(p *model.ConditionalAccessPolicy) { p.State = model.CAStateEnabled }); err != nil {
				t.Fatal(err)
			}
		}, "state is"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tn := setup(t)
			c.prep(t, tn)
			rep, err := Verify(context.Background(), tn.Reader(), cfg, plan())
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verified() {
				t.Fatal("expected not verified")
			}
			if got := strings.Join(rep.Checks[0].Problems, "\n"); !strings.Contains(got, c.want) {
				t.Fatalf("problems %q do not mention %q", got, c.want)
			}
		})
	}
}

// fakeReader serves one policy (or none, if p.ID is empty) through both
// read methods, so tests do not depend on which one Verify uses.
type fakeReader struct {
	p      model.ConditionalAccessPolicy
	tenant string
	err    error
}

func (f fakeReader) ReadSnapshot(context.Context) (model.Snapshot, error) {
	if f.err != nil {
		return model.Snapshot{}, f.err
	}
	s := model.Snapshot{TenantID: tenantID}
	if f.tenant != "" {
		s.TenantID = f.tenant
	}
	if f.p.ID != "" {
		s.Policies = []model.ConditionalAccessPolicy{f.p}
	}
	return s, nil
}

func (f fakeReader) ReadConditionalAccessPolicy(context.Context, string) (model.ConditionalAccessPolicy, error) {
	if f.err != nil {
		return model.ConditionalAccessPolicy{}, f.err
	}
	if f.p.ID == "" {
		return model.ConditionalAccessPolicy{}, entra.ErrNotFound
	}
	return f.p, nil
}

func reported() model.ConditionalAccessPolicy {
	return model.ConditionalAccessPolicy{
		ID: adminPolicy, Version: "gen-1", State: model.CAStateReportOnly,
		ExcludeUsers: []string{"user-breakglass-01", "user-breakglass-02"},
	}
}

func TestFakeReaderCases(t *testing.T) {
	cases := map[string]struct {
		mutate func(*model.ConditionalAccessPolicy)
		want   string
	}{
		"version unchanged": {func(p *model.ConditionalAccessPolicy) { p.Version = "v7" }, "no write is visible"},
		"wrong object":      {func(p *model.ConditionalAccessPolicy) { p.ID = "ca-other" }, "no longer exists"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := reported()
			c.mutate(&p)
			rep, err := Verify(context.Background(), fakeReader{p: p}, cfg, plan())
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verified() || !strings.Contains(strings.Join(rep.Checks[0].Problems, "\n"), c.want) {
				t.Fatalf("report %+v", rep)
			}
		})
	}
	if rep, err := Verify(context.Background(), fakeReader{p: reported()}, cfg, plan()); err != nil || !rep.Verified() {
		t.Fatalf("control case: %+v %v", rep, err)
	}
}

func TestTargetDeleted(t *testing.T) {
	rep, err := Verify(context.Background(), fakeReader{}, cfg, plan())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verified() || !strings.Contains(rep.Checks[0].Problems[0], "no longer exists") {
		t.Fatalf("report %+v", rep)
	}
}

// Review finding: Verify must bind to the plan's tenant.
func TestRejectsOtherTenant(t *testing.T) {
	tn := setup(t)
	write(t, tn)
	p := plan()
	p.TenantID = "tenant-other.example.test"
	rep, err := Verify(context.Background(), tn.Reader(), cfg, p)
	if err == nil && rep.Verified() {
		t.Fatal("verified a plan for another tenant")
	}
	rep, err = Verify(context.Background(), fakeReader{p: reported(), tenant: "tenant-other.example.test"}, cfg, plan())
	if err == nil && rep.Verified() {
		t.Fatal("verified against a reader for another tenant")
	}
}

// Review finding: observed state must be validated, not just compared.
func TestRejectsInvalidObservedState(t *testing.T) {
	for name, mutate := range map[string]func(*model.ConditionalAccessPolicy){
		"empty version":     func(p *model.ConditionalAccessPolicy) { p.Version = "" },
		"unknown state":     func(p *model.ConditionalAccessPolicy) { p.State = "paused" },
		"bad excluded user": func(p *model.ConditionalAccessPolicy) { p.ExcludeUsers = append(p.ExcludeUsers, "") },
	} {
		t.Run(name, func(t *testing.T) {
			p := reported()
			mutate(&p)
			rep, err := Verify(context.Background(), fakeReader{p: p}, cfg, plan())
			if err == nil && rep.Verified() {
				t.Fatal("verified an invalid observed policy")
			}
		})
	}
}

func TestErrors(t *testing.T) {
	tn := setup(t)
	if _, err := Verify(context.Background(), nil, cfg, plan()); err == nil {
		t.Error("nil reader accepted")
	}
	if _, err := Verify(context.Background(), tn.Reader(), Config{}, plan()); err == nil {
		t.Error("missing break-glass config accepted")
	}
	if _, err := Verify(context.Background(), tn.Reader(), cfg, model.Plan{}); err == nil {
		t.Error("invalid plan accepted")
	}
	if _, err := Verify(context.Background(), fakeReader{err: errors.New("io")}, cfg, plan()); err == nil {
		t.Error("read error swallowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, tn.Reader(), cfg, plan()); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: got %v", err)
	}
}
