package mockentra

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
	"github.com/yukiigarashi-dev/kodis/internal/policy"
)

const (
	adminPolicy = "ca-require-mfa-admins"
	tenantID    = "tenant-contoso.example.test"
)

func scenario(name string) string {
	return filepath.Join("..", "..", "testdata", "scenarios", name, "tenant.json")
}

func newTenant(t *testing.T) *Tenant {
	t.Helper()
	f, err := LoadFixture(scenario("baseline"))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := New(f)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func read(t *testing.T, tn *Tenant, id string) model.ConditionalAccessPolicy {
	t.Helper()
	p, err := tn.Reader().ReadConditionalAccessPolicy(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAllScenarioFixturesLoad(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "scenarios", "*", "tenant.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no scenario fixtures found")
	}
	for _, p := range paths {
		f, err := LoadFixture(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if !strings.HasSuffix(f.TenantID, ".example.test") {
			t.Errorf("%s: tenant %q must use the example.test domain", p, f.TenantID)
		}
	}
}

// TestScenarioExpectations ties fixtures to the policy engine so a fixture
// edit cannot silently change what a scenario exercises.
func TestScenarioExpectations(t *testing.T) {
	cfg := policy.Config{TenantID: tenantID, BreakGlassUserIDs: []string{"user-breakglass-01", "user-breakglass-02"}}
	plan := model.Plan{
		Schema:     model.PlanSchemaV1,
		ID:         "plan-0001",
		TenantID:   tenantID,
		CreatedAt:  time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC),
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
	for name, wantAllowed := range map[string]bool{"baseline": true, "breakglass-not-excluded": false} {
		f, err := LoadFixture(scenario(name))
		if err != nil {
			t.Fatal(err)
		}
		if got := policy.Evaluate(cfg, plan, f.Snapshot()).Allowed(); got != wantAllowed {
			t.Errorf("%s: allowed=%v, want %v", name, got, wantAllowed)
		}
	}
}

func TestDecodeFixtureRejects(t *testing.T) {
	base := `{"tenantId":"tenant-a.example.test","users":[{"id":"u1","displayName":"U"}],"roles":[{"id":"r1","displayName":"R"}],` +
		`"policies":[{"id":"p1","version":"v1","displayName":"P","state":"disabled","includeUsers":["All"],"excludeUsers":["u1"],"includeRoles":["r1"],"grantControls":["mfa"]}]}`
	if _, err := DecodeFixture([]byte(base)); err != nil {
		t.Fatalf("base fixture rejected: %v", err)
	}
	cases := map[string][2]string{
		"unknown excluded user": {`"excludeUsers":["u1"]`, `"excludeUsers":["u2"]`},
		"unknown included user": {`"includeUsers":["All"]`, `"includeUsers":["u9"]`},
		"unknown role":          {`"includeRoles":["r1"]`, `"includeRoles":["r9"]`},
		"duplicate user":        {`"users":[{"id":"u1","displayName":"U"}]`, `"users":[{"id":"u1","displayName":"U"},{"id":"u1","displayName":"U"}]`},
		"user named All":        {`"users":[{"id":"u1","displayName":"U"}]`, `"users":[{"id":"u1","displayName":"U"},{"id":"All","displayName":"U"}]`},
		"reserved version":      {`"version":"v1"`, `"version":"gen-1"`},
		"unknown state":         {`"state":"disabled"`, `"state":"off"`},
		"unknown field":         {`"tenantId"`, `"realTenant":true,"tenantId"`},
		"duplicate key":         {`"tenantId":"tenant-a.example.test"`, `"tenantId":"tenant-a.example.test","tenantId":"tenant-b.example.test"`},
		"duplicate policy":      {`"grantControls":["mfa"]}]`, `"grantControls":["mfa"]},{"id":"p1","version":"v2","displayName":"P","state":"disabled","includeUsers":[],"excludeUsers":[],"includeRoles":[],"grantControls":[]}]`},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(base, r[0]) {
				t.Fatalf("base does not contain %q", r[0])
			}
			if _, err := DecodeFixture([]byte(strings.Replace(base, r[0], r[1], 1))); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestReadReturnsCopies(t *testing.T) {
	tn := newTenant(t)
	s, err := tn.Reader().ReadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Policies[0].ExcludeUsers[0] = "tampered"
	s.Policies[0].State = model.CAStateEnabled
	p := read(t, tn, adminPolicy)
	p.GrantControls[0] = "tampered"
	again := read(t, tn, adminPolicy)
	if again.ExcludeUsers[0] != "user-breakglass-01" || again.State != model.CAStateDisabled || again.GrantControls[0] != model.GrantMFA {
		t.Fatalf("caller mutation leaked into tenant: %+v", again)
	}
}

func TestNewDoesNotAliasFixture(t *testing.T) {
	f, err := LoadFixture(scenario("baseline"))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := New(f)
	if err != nil {
		t.Fatal(err)
	}
	f.Policies[0].ExcludeUsers[0] = "tampered"
	if read(t, tn, adminPolicy).ExcludeUsers[0] != "user-breakglass-01" {
		t.Fatal("fixture mutation leaked into tenant")
	}
}

func TestSnapshotOrderIsStable(t *testing.T) {
	tn := newTenant(t)
	s, err := tn.Reader().ReadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ca-require-mfa-admins", "ca-block-legacy-auth", "ca-require-mfa-all-users"}
	for i, p := range s.Policies {
		if p.ID != want[i] {
			t.Fatalf("order %d: got %s want %s", i, p.ID, want[i])
		}
	}
}

func TestCompareAndSwap(t *testing.T) {
	tn := newTenant(t)
	ctx := context.Background()
	w := tn.Writer()

	v, err := w.SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly)
	if err != nil {
		t.Fatal(err)
	}
	p := read(t, tn, adminPolicy)
	if p.State != model.CAStateReportOnly || p.Version != v || v == "v7" {
		t.Fatalf("write not applied: %+v (returned %s)", p, v)
	}
	if got := tn.Writes(); len(got) != 1 || got[0].OldVersion != "v7" || got[0].NewVersion != v {
		t.Fatalf("write log %+v", got)
	}

	// Reusing the old version must conflict and change nothing.
	if _, err := w.SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateEnabled); !errors.Is(err, entra.ErrVersionConflict) {
		t.Fatalf("got %v, want version conflict", err)
	}
	if read(t, tn, adminPolicy).State != model.CAStateReportOnly {
		t.Fatal("conflicting write was applied")
	}
}

func TestWriteRejects(t *testing.T) {
	tn := newTenant(t)
	ctx := context.Background()
	w := tn.Writer()
	if _, err := w.SetConditionalAccessState(ctx, "ca-missing", "v7", model.CAStateReportOnly); !errors.Is(err, entra.ErrNotFound) {
		t.Fatalf("missing: got %v", err)
	}
	if _, err := w.SetConditionalAccessState(ctx, adminPolicy, "v7", "off"); err == nil {
		t.Fatal("unknown state accepted")
	}
	if _, err := w.SetConditionalAccessState(ctx, adminPolicy, "", model.CAStateReportOnly); !errors.Is(err, entra.ErrVersionConflict) {
		t.Fatalf("empty version: got %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := w.SetConditionalAccessState(cancelled, adminPolicy, "v7", model.CAStateReportOnly); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: got %v", err)
	}
	if _, err := tn.Reader().ReadSnapshot(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read: got %v", err)
	}
	if p := read(t, tn, adminPolicy); p.Version != "v7" || p.State != model.CAStateDisabled || len(tn.Writes()) != 0 {
		t.Fatalf("rejected writes changed state: %+v", p)
	}
}

func TestVersionsNeverRepeat(t *testing.T) {
	tn := newTenant(t)
	ctx := context.Background()
	seen := map[string]bool{"v7": true}
	v := "v7"
	states := []model.CAState{model.CAStateReportOnly, model.CAStateDisabled}
	for i := range 10 {
		next, err := tn.Writer().SetConditionalAccessState(ctx, adminPolicy, v, states[i%2])
		if err != nil {
			t.Fatal(err)
		}
		if seen[next] {
			t.Fatalf("version %s reused (ABA)", next)
		}
		seen[next] = true
		v = next
	}
}

func TestConcurrentWritersExactlyOneWins(t *testing.T) {
	tn := newTenant(t)
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tn.Writer().SetConditionalAccessState(context.Background(), adminPolicy, "v7", model.CAStateReportOnly)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, entra.ErrVersionConflict):
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok != 1 || len(tn.Writes()) != 1 {
		t.Fatalf("%d writers succeeded, %d writes recorded; want exactly 1", ok, len(tn.Writes()))
	}
}

func TestFaults(t *testing.T) {
	ctx := context.Background()

	t.Run("write error", func(t *testing.T) {
		tn := newTenant(t)
		tn.InjectFault(FaultWriteError)
		if _, err := tn.Writer().SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly); !errors.Is(err, ErrInjected) {
			t.Fatalf("got %v", err)
		}
		if p := read(t, tn, adminPolicy); p.State != model.CAStateDisabled || p.Version != "v7" {
			t.Fatalf("failed write changed state: %+v", p)
		}
	})

	t.Run("drop write", func(t *testing.T) {
		tn := newTenant(t)
		tn.InjectFault(FaultDropWrite)
		v, err := tn.Writer().SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly)
		if err != nil || v == "" {
			t.Fatalf("dropped write must look successful: %q %v", v, err)
		}
		if p := read(t, tn, adminPolicy); p.State != model.CAStateDisabled || p.Version != "v7" {
			t.Fatalf("dropped write was applied: %+v", p)
		}
	})

	t.Run("concurrent modify", func(t *testing.T) {
		tn := newTenant(t)
		tn.InjectFault(FaultConcurrentModify)
		if _, err := tn.Writer().SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly); !errors.Is(err, entra.ErrVersionConflict) {
			t.Fatalf("got %v", err)
		}
		if p := read(t, tn, adminPolicy); p.State != model.CAStateDisabled || p.Version == "v7" {
			t.Fatalf("want unchanged state with bumped version, got %+v", p)
		}
	})

	t.Run("stale read", func(t *testing.T) {
		tn := newTenant(t)
		tn.InjectFault(FaultStaleRead)
		v, err := tn.Writer().SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly)
		if err != nil {
			t.Fatal(err)
		}
		if p := read(t, tn, adminPolicy); p.State != model.CAStateDisabled || p.Version != "v7" {
			t.Fatalf("stale reader saw new state: %+v", p)
		}
		tn.ClearStaleReads()
		if p := read(t, tn, adminPolicy); p.State != model.CAStateReportOnly || p.Version != v {
			t.Fatalf("write lost: %+v", p)
		}
	})

	t.Run("faults are consumed in order", func(t *testing.T) {
		tn := newTenant(t)
		tn.InjectFault(FaultWriteError)
		w := tn.Writer()
		if _, err := w.SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly); err == nil {
			t.Fatal("first write should fail")
		}
		if _, err := w.SetConditionalAccessState(ctx, adminPolicy, "v7", model.CAStateReportOnly); err != nil {
			t.Fatalf("second write should succeed: %v", err)
		}
	})
}

func TestModify(t *testing.T) {
	tn := newTenant(t)
	if err := tn.Modify(adminPolicy, func(p *model.ConditionalAccessPolicy) { p.ExcludeUsers = nil }); err != nil {
		t.Fatal(err)
	}
	p := read(t, tn, adminPolicy)
	if len(p.ExcludeUsers) != 0 || p.Version == "v7" {
		t.Fatalf("modify not applied with new version: %+v", p)
	}
	if err := tn.Modify("ca-missing", func(*model.ConditionalAccessPolicy) {}); !errors.Is(err, entra.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	before := read(t, tn, adminPolicy)
	err := tn.Modify(adminPolicy, func(p *model.ConditionalAccessPolicy) {
		p.GrantControls[0] = "bad value"
	})
	if err == nil {
		t.Fatal("invalid modify accepted")
	}
	if after := read(t, tn, adminPolicy); after.GrantControls[0] != before.GrantControls[0] || after.Version != before.Version {
		t.Fatalf("rejected modify changed state: %+v", after)
	}
}
