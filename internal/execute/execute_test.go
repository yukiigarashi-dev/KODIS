package execute

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/approve"
	"github.com/yukiigarashi-dev/kodis/internal/audit"
	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
	"github.com/yukiigarashi-dev/kodis/internal/policy"
)

const (
	tenantID    = "tenant-contoso.example.test"
	adminPolicy = "ca-require-mfa-admins"
	pilotPolicy = "ca-require-mfa-all-users"
)

// The persistent audit log must be usable as the executor's ledger.
var _ Ledger = (*audit.Log)(nil)

var t0 = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

type env struct {
	tenant *mockentra.Tenant
	signer *approve.Signer
	cfg    Config
	clock  *clock
}

type clock struct {
	mu  sync.Mutex
	now time.Time
	// step is added after every call, to simulate time passing.
	step time.Duration
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.now
	c.now = c.now.Add(c.step)
	return n
}

func setup(t *testing.T) *env {
	t.Helper()
	f, err := mockentra.LoadFixture(filepath.Join("..", "..", "testdata", "scenarios", "baseline", "tenant.json"))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := mockentra.New(f)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := approve.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := approve.NewSigner("alice", priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := approve.NewVerifier([]approve.TrustedKey{{ApproverID: "alice", PublicKey: pub}})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: t0}
	return &env{
		tenant: tn,
		signer: s,
		clock:  c,
		cfg: Config{
			Policy:   policy.Config{TenantID: tenantID, BreakGlassUserIDs: []string{"user-breakglass-01", "user-breakglass-02"}},
			Verifier: v,
			Reader:   tn.Reader(),
			Writer:   tn.Writer(),
			Ledger:   &MemoryLedger{},
			Now:      c.Now,
		},
	}
}

func action(id, target, version string) model.Action {
	return model.Action{
		ID:              id,
		Operation:       model.OpSetConditionalAccessState,
		Target:          model.ResourceRef{Kind: model.KindConditionalAccessPolicy, ID: target},
		ExpectedVersion: version,
		ExpectedState:   string(model.CAStateDisabled),
		DesiredState:    string(model.CAStateReportOnly),
	}
}

func plan(actions ...model.Action) model.Plan {
	if len(actions) == 0 {
		actions = []model.Action{action("action-0001", adminPolicy, "v7")}
	}
	return model.Plan{
		Schema:     model.PlanSchemaV1,
		ID:         "plan-0001",
		TenantID:   tenantID,
		CreatedAt:  t0.Add(-time.Minute),
		FindingIDs: []string{"finding-0001"},
		Actions:    actions,
	}
}

func (e *env) approve(t *testing.T, p model.Plan) model.Approval {
	t.Helper()
	a, err := e.signer.Approve(p, t0, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *env) executor(t *testing.T) *Executor {
	t.Helper()
	x, err := New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (e *env) state(t *testing.T, id string) model.ConditionalAccessPolicy {
	t.Helper()
	p, err := e.tenant.Reader().ReadConditionalAccessPolicy(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHappyPath(t *testing.T) {
	e := setup(t)
	p := plan()
	r := e.executor(t).Execute(context.Background(), p, e.approve(t, p))
	if r.Status != StatusCompleted {
		t.Fatalf("status %s, reasons %v, steps %+v", r.Status, r.Reasons, r.Steps)
	}
	if got := e.state(t, adminPolicy); got.State != model.CAStateReportOnly || got.Version != r.Steps[0].NewVersion {
		t.Fatalf("tenant state %+v, step %+v", got, r.Steps[0])
	}
	if len(e.tenant.Writes()) != 1 {
		t.Fatalf("writes %+v", e.tenant.Writes())
	}
}

func TestZeroResultIsNotCompleted(t *testing.T) {
	if (Result{}).Status == StatusCompleted {
		t.Fatal("zero Result must not mean completed")
	}
}

// TestDeniedBeforeAnyWrite covers every pre-write check. In each case the
// tenant must be untouched.
func TestDeniedBeforeAnyWrite(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, e *env) Result
		want string
	}{
		{"zero approval", func(t *testing.T, e *env) Result {
			return e.executor(t).Execute(context.Background(), plan(), model.Approval{})
		}, "approval"},
		{"invalid plan", func(t *testing.T, e *env) Result {
			return e.executor(t).Execute(context.Background(), model.Plan{}, e.approve(t, plan()))
		}, "invalid plan"},
		{"plan changed after approval", func(t *testing.T, e *env) Result {
			a := e.approve(t, plan())
			q := plan()
			q.Actions[0].DesiredState = string(model.CAStateEnabled)
			return e.executor(t).Execute(context.Background(), q, a)
		}, "plan_mismatch"},
		{"signature tampered", func(t *testing.T, e *env) Result {
			a := e.approve(t, plan())
			a.Signature[3] ^= 0x80
			return e.executor(t).Execute(context.Background(), plan(), a)
		}, "bad_signature"},
		{"untrusted approver key", func(t *testing.T, e *env) Result {
			_, priv, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
			if err != nil {
				t.Fatal(err)
			}
			s, err := approve.NewSigner("alice", priv)
			if err != nil {
				t.Fatal(err)
			}
			a, err := s.Approve(plan(), t0, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return e.executor(t).Execute(context.Background(), plan(), a)
		}, "unknown_key"},
		{"approval expired", func(t *testing.T, e *env) Result {
			a := e.approve(t, plan())
			e.clock.now = t0.Add(15 * time.Minute)
			return e.executor(t).Execute(context.Background(), plan(), a)
		}, "expired"},
		{"approval not yet valid", func(t *testing.T, e *env) Result {
			a := e.approve(t, plan())
			e.clock.now = t0.Add(-time.Second)
			return e.executor(t).Execute(context.Background(), plan(), a)
		}, "not_yet_valid"},
		{"target changed since planning", func(t *testing.T, e *env) Result {
			p := plan()
			a := e.approve(t, p)
			if err := e.tenant.Modify(adminPolicy, func(*model.ConditionalAccessPolicy) {}); err != nil {
				t.Fatal(err)
			}
			return e.executor(t).Execute(context.Background(), p, a)
		}, "version_mismatch"},
		{"break-glass exclusion removed after approval", func(t *testing.T, e *env) Result {
			p := plan()
			a := e.approve(t, p)
			if err := e.tenant.Modify(adminPolicy, func(c *model.ConditionalAccessPolicy) { c.ExcludeUsers = nil }); err != nil {
				t.Fatal(err)
			}
			return e.executor(t).Execute(context.Background(), p, a)
		}, "break_glass_not_excluded"},
		{"policy config for other tenant", func(t *testing.T, e *env) Result {
			e.cfg.Policy.TenantID = "tenant-other.example.test"
			p := plan()
			return e.executor(t).Execute(context.Background(), p, e.approve(t, p))
		}, "tenant_mismatch"},
		{"re-read fails", func(t *testing.T, e *env) Result {
			p := plan()
			a := e.approve(t, p)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return e.executor(t).Execute(ctx, p, a)
		}, "re-read"},
		{"ledger refuses", func(t *testing.T, e *env) Result {
			e.cfg.Ledger = refusingLedger{}
			p := plan()
			return e.executor(t).Execute(context.Background(), p, e.approve(t, p))
		}, "ledger"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t)
			r := c.run(t, e)
			if r.Status != StatusDenied {
				t.Fatalf("status %s, want denied (reasons %v)", r.Status, r.Reasons)
			}
			if !strings.Contains(strings.Join(r.Reasons, "\n"), c.want) {
				t.Fatalf("reasons %v do not mention %q", r.Reasons, c.want)
			}
			if len(r.Steps) != 0 || len(e.tenant.Writes()) != 0 {
				t.Fatalf("denied run wrote: steps %+v, writes %+v", r.Steps, e.tenant.Writes())
			}
		})
	}
}

type refusingLedger struct{}

func (refusingLedger) Claim(model.Digest) error { return errors.New("ledger unavailable") }

func TestBuiltinAllowlistIsIndependentOfPolicy(t *testing.T) {
	ok := action("a", adminPolicy, "v7")
	if err := checkBuiltin(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*model.Action){
		"enforce": func(a *model.Action) { a.DesiredState = string(model.CAStateEnabled) },
		"disable": func(a *model.Action) {
			a.ExpectedState, a.DesiredState = string(model.CAStateReportOnly), string(model.CAStateDisabled)
		},
		"other operation": func(a *model.Action) { a.Operation = "conditionalAccess.delete" },
		"other kind":      func(a *model.Action) { a.Target.Kind = "user" },
	} {
		a := ok
		mutate(&a)
		if err := checkBuiltin(a); err == nil {
			t.Errorf("%s: allowed by builtin allowlist", name)
		}
	}
}

func TestBuiltinAllowlistIsCheckedByExecute(t *testing.T) {
	e := setup(t)
	p := plan()
	p.Actions[0].DesiredState = string(model.CAStateEnabled)
	r := e.executor(t).Execute(context.Background(), p, e.approve(t, p))
	if r.Status != StatusDenied || !strings.Contains(strings.Join(r.Reasons, "\n"), "executor allowlist") {
		t.Fatalf("status %s, reasons %v", r.Status, r.Reasons)
	}
}

// staticTenant never changes version, so compare-and-swap cannot stop a
// replay; only the ledger can.
type staticTenant struct {
	snap   model.Snapshot
	writes atomic.Int32
}

func (s *staticTenant) ReadSnapshot(context.Context) (model.Snapshot, error) { return s.snap, nil }
func (s *staticTenant) ReadConditionalAccessPolicy(_ context.Context, id string) (model.ConditionalAccessPolicy, error) {
	p, _ := s.snap.Policy(id)
	return p, nil
}
func (s *staticTenant) SetConditionalAccessState(context.Context, string, string, model.CAState) (string, error) {
	s.writes.Add(1)
	return "v7", nil
}

func staticEnv(t *testing.T) (*env, *staticTenant) {
	t.Helper()
	e := setup(t)
	snap, err := e.tenant.Reader().ReadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st := &staticTenant{snap: snap}
	e.cfg.Reader, e.cfg.Writer = st, st
	return e, st
}

func TestLedgerStopsReplayWithoutCAS(t *testing.T) {
	e, st := staticEnv(t)
	x := e.executor(t)
	p := plan()
	a := e.approve(t, p)
	if r := x.Execute(context.Background(), p, a); r.Status != StatusCompleted {
		t.Fatalf("first run %s %v", r.Status, r.Reasons)
	}
	r := x.Execute(context.Background(), p, a)
	if r.Status != StatusDenied || !strings.Contains(strings.Join(r.Reasons, "\n"), "ledger") || st.writes.Load() != 1 {
		t.Fatalf("replay: status %s reasons %v writes %d", r.Status, r.Reasons, st.writes.Load())
	}
}

func TestLedgerSerializesConcurrentRunsWithoutCAS(t *testing.T) {
	e, st := staticEnv(t)
	x := e.executor(t)
	p := plan()
	a := e.approve(t, p)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x.Execute(context.Background(), p, a)
		}()
	}
	wg.Wait()
	if st.writes.Load() != 1 {
		t.Fatalf("%d writes, want 1", st.writes.Load())
	}
}

func TestReplayIsRefused(t *testing.T) {
	e := setup(t)
	x := e.executor(t)
	p := plan()
	a := e.approve(t, p)
	if r := x.Execute(context.Background(), p, a); r.Status != StatusCompleted {
		t.Fatalf("first run %s %v", r.Status, r.Reasons)
	}
	// Put the target back so only the ledger can stop the replay.
	if err := e.tenant.Modify(adminPolicy, func(c *model.ConditionalAccessPolicy) { c.State = model.CAStateDisabled }); err != nil {
		t.Fatal(err)
	}
	r := x.Execute(context.Background(), p, a)
	if r.Status != StatusDenied || len(e.tenant.Writes()) != 1 {
		t.Fatalf("replay: status %s reasons %v writes %d", r.Status, r.Reasons, len(e.tenant.Writes()))
	}
}

func TestConcurrentExecutionWritesOnce(t *testing.T) {
	e := setup(t)
	x := e.executor(t)
	p := plan()
	a := e.approve(t, p)
	var completed atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if x.Execute(context.Background(), p, a).Status == StatusCompleted {
				completed.Add(1)
			}
		}()
	}
	wg.Wait()
	if completed.Load() != 1 || len(e.tenant.Writes()) != 1 {
		t.Fatalf("%d completed, %d writes; want exactly 1", completed.Load(), len(e.tenant.Writes()))
	}
}

func TestWriteFailures(t *testing.T) {
	for name, fault := range map[string]mockentra.Fault{
		"write error":       mockentra.FaultWriteError,
		"concurrent modify": mockentra.FaultConcurrentModify,
	} {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			p := plan()
			a := e.approve(t, p)
			e.tenant.InjectFault(fault)
			r := e.executor(t).Execute(context.Background(), p, a)
			if r.Status != StatusFailed || r.Steps[0].Status != StepFailed || r.Steps[0].Err == "" {
				t.Fatalf("result %+v", r)
			}
			if got := e.state(t, adminPolicy); got.State != model.CAStateDisabled || len(e.tenant.Writes()) != 0 {
				t.Fatalf("failed write changed state: %+v", got)
			}
		})
	}
}

func twoActionEnv(t *testing.T) (*env, model.Plan) {
	t.Helper()
	e := setup(t)
	if err := e.tenant.Modify(pilotPolicy, func(c *model.ConditionalAccessPolicy) { c.State = model.CAStateDisabled }); err != nil {
		t.Fatal(err)
	}
	pv := e.state(t, pilotPolicy).Version
	return e, plan(action("action-0001", adminPolicy, "v7"), action("action-0002", pilotPolicy, pv))
}

func TestTwoActionsCompleted(t *testing.T) {
	e, p := twoActionEnv(t)
	r := e.executor(t).Execute(context.Background(), p, e.approve(t, p))
	if r.Status != StatusCompleted {
		t.Fatalf("status %s, steps %+v", r.Status, r.Steps)
	}
	for _, id := range []string{adminPolicy, pilotPolicy} {
		if e.state(t, id).State != model.CAStateReportOnly {
			t.Fatalf("%s not written", id)
		}
	}
	// Each write must be a CAS on that action's own expected version.
	for i, w := range e.tenant.Writes() {
		if w.OldVersion != p.Actions[i].ExpectedVersion {
			t.Fatalf("write %d used version %s, plan expected %s", i, w.OldVersion, p.Actions[i].ExpectedVersion)
		}
	}
}

func TestPartialFailureStops(t *testing.T) {
	e, p := twoActionEnv(t)
	a := e.approve(t, p)
	e.tenant.InjectFault(mockentra.FaultNone)
	e.tenant.InjectFault(mockentra.FaultWriteError)
	r := e.executor(t).Execute(context.Background(), p, a)
	if r.Status != StatusPartial {
		t.Fatalf("status %s, steps %+v", r.Status, r.Steps)
	}
	if r.Steps[0].Status != StepWritten || r.Steps[1].Status != StepFailed {
		t.Fatalf("steps %+v", r.Steps)
	}
	if e.state(t, adminPolicy).State != model.CAStateReportOnly || e.state(t, pilotPolicy).State != model.CAStateDisabled {
		t.Fatal("tenant state does not match reported steps")
	}
}

func TestStopsWhenApprovalExpiresMidRun(t *testing.T) {
	e, p := twoActionEnv(t)
	a, err := e.signer.Approve(p, t0, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Calls: verify (t0), before write 1 (t0+2s), before write 2 (t0+4s).
	e.clock.step = 2 * time.Second
	r := e.executor(t).Execute(context.Background(), p, a)
	if r.Status != StatusPartial || r.Steps[0].Status != StepWritten || r.Steps[1].Status != StepFailed {
		t.Fatalf("result %+v", r)
	}
	if !strings.Contains(r.Steps[1].Err, "expired") {
		t.Fatalf("step error %q", r.Steps[1].Err)
	}
	if len(e.tenant.Writes()) != 1 {
		t.Fatalf("writes %d, want 1", len(e.tenant.Writes()))
	}
}

func TestStopsWhenContextCancelledMidRun(t *testing.T) {
	e, p := twoActionEnv(t)
	a := e.approve(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	e.cfg.Writer = cancelAfterWrite{w: e.tenant.Writer(), cancel: cancel}
	r := e.executor(t).Execute(ctx, p, a)
	if r.Status != StatusPartial || r.Steps[1].Status != StepFailed || len(e.tenant.Writes()) != 1 {
		t.Fatalf("result %+v writes %d", r, len(e.tenant.Writes()))
	}
}

type cancelAfterWrite struct {
	w      entra.Writer
	cancel context.CancelFunc
}

// SetConditionalAccessState ignores ctx on purpose, so only the
// executor's own cancellation check can stop the second write.
func (c cancelAfterWrite) SetConditionalAccessState(_ context.Context, id, v string, s model.CAState) (string, error) {
	defer c.cancel()
	return c.w.SetConditionalAccessState(context.Background(), id, v, s)
}

// TestDroppedWriteIsNotDetectedHere documents the limit of the executor:
// it reports what the writer returned. internal/verify must catch this.
func TestDroppedWriteIsNotDetectedHere(t *testing.T) {
	e := setup(t)
	p := plan()
	a := e.approve(t, p)
	e.tenant.InjectFault(mockentra.FaultDropWrite)
	r := e.executor(t).Execute(context.Background(), p, a)
	if r.Status != StatusCompleted {
		t.Fatalf("status %s", r.Status)
	}
	if e.state(t, adminPolicy).State != model.CAStateDisabled {
		t.Fatal("fault injection did not drop the write")
	}
}

func TestNewRequiresAllDependencies(t *testing.T) {
	e := setup(t)
	for name, mutate := range map[string]func(*Config){
		"verifier": func(c *Config) { c.Verifier = nil },
		"reader":   func(c *Config) { c.Reader = nil },
		"writer":   func(c *Config) { c.Writer = nil },
		"ledger":   func(c *Config) { c.Ledger = nil },
		"clock":    func(c *Config) { c.Now = nil },
	} {
		c := e.cfg
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
}

func TestZeroExecutorDenies(t *testing.T) {
	e := setup(t)
	p := plan()
	a := e.approve(t, p)
	x := &Executor{cfg: Config{Now: e.clock.Now}}
	if r := x.Execute(context.Background(), p, a); r.Status != StatusDenied {
		t.Fatalf("status %s", r.Status)
	}
}
