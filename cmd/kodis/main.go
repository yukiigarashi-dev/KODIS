// Command kodis runs Inspect → Evaluate → Plan → Approve → Execute → Verify
// against a simulated Entra tenant loaded from a synthetic fixture. It has
// no way to connect to a real tenant.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/approve"
	"github.com/yukiigarashi-dev/kodis/internal/audit"
	"github.com/yukiigarashi-dev/kodis/internal/evaluate"
	"github.com/yukiigarashi-dev/kodis/internal/execute"
	"github.com/yukiigarashi-dev/kodis/internal/inspect"
	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
	"github.com/yukiigarashi-dev/kodis/internal/plan"
	"github.com/yukiigarashi-dev/kodis/internal/policy"
	"github.com/yukiigarashi-dev/kodis/internal/verify"
)

// Exit codes.
const (
	exitOK            = 0
	exitError         = 1
	exitUsage         = 2
	exitNothingToDo   = 3
	exitPolicyDenied  = 4
	exitNotApproved   = 5
	exitNotExecuted   = 6
	exitNotVerified   = 7
	approvalTTL       = 15 * time.Minute
	approvalPrefixLen = 12
	maxConfigBytes    = 64 << 10
)

// env is everything the commands touch outside their arguments, so tests
// can drive them deterministically.
type env struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	now            func() time.Time
	rand           io.Reader
}

func main() {
	os.Exit(run(os.Args[1:], env{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now, rand: rand.Reader}))
}

func run(args []string, e env) int {
	if len(args) == 0 {
		usage(e.stderr)
		return exitUsage
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], e)
	case "run":
		return cmdRun(args[1:], e)
	case "audit-verify":
		return cmdAuditVerify(args[1:], e)
	default:
		usage(e.stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  kodis keygen [-key PATH] [-pub PATH]
  kodis run -config PATH -fixture PATH -audit PATH -approver ID [-key PATH] [-pub PATH] [-fault NAME]
  kodis audit-verify -audit PATH

kodis only operates on a simulated tenant loaded from a synthetic fixture.
`)
}

func defaultKeyPaths() (string, string) {
	k, err := approve.DefaultKeyPath()
	if err != nil {
		return "", ""
	}
	return k, strings.TrimSuffix(k, ".key") + ".pub"
}

func cmdKeygen(args []string, e env) int {
	defKey, defPub := defaultKeyPaths()
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	keyPath := fs.String("key", defKey, "private key path (created with mode 0600, never overwritten)")
	pubPath := fs.String("pub", defPub, "public key path")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *keyPath == "" || *pubPath == "" {
		return exitUsage
	}
	pub, priv, err := approve.GenerateKey(e.rand)
	if err != nil {
		return fail(e, "generate key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*keyPath), 0o700); err != nil {
		return fail(e, "%v", err)
	}
	if err := approve.WritePrivateKey(*keyPath, priv); err != nil {
		return fail(e, "write private key: %v", err)
	}
	if err := approve.WritePublicKey(*pubPath, pub); err != nil {
		return fail(e, "write public key: %v", err)
	}
	fmt.Fprintf(e.stdout, "key id: %s\n", approve.KeyID(pub))
	return exitOK
}

func cmdAuditVerify(args []string, e env) int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	path := fs.String("audit", "", "audit log path")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *path == "" {
		return exitUsage
	}
	f, err := os.Open(*path)
	if err != nil {
		return fail(e, "%v", err)
	}
	defer f.Close()
	recs, err := audit.Chain(f)
	if err != nil {
		return fail(e, "%v", err)
	}
	head := model.Digest{}
	if len(recs) > 0 {
		head = recs[len(recs)-1].Hash
	}
	fmt.Fprintf(e.stdout, "audit log OK: %d records, head %s\n", len(recs), head)
	return exitOK
}

// config is operator configuration for one tenant.
type config struct {
	TenantID          string   `json:"tenantId"`
	BreakGlassUserIDs []string `json:"breakGlassUserIds"`
}

func loadConfig(path string) (config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var c config
	if err := model.DecodeStrict(b, maxConfigBytes, &c); err != nil {
		return config{}, fmt.Errorf("%s: %w", path, err)
	}
	if c.TenantID == "" || len(c.BreakGlassUserIDs) == 0 {
		return config{}, fmt.Errorf("%s: tenantId and breakGlassUserIds are required", path)
	}
	return c, nil
}

var faults = map[string]mockentra.Fault{
	"":                  mockentra.FaultNone,
	"write-error":       mockentra.FaultWriteError,
	"drop-write":        mockentra.FaultDropWrite,
	"concurrent-modify": mockentra.FaultConcurrentModify,
	"stale-read":        mockentra.FaultStaleRead,
}

func cmdRun(args []string, e env) int {
	defKey, defPub := defaultKeyPaths()
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	cfgPath := fs.String("config", "", "operator config (tenantId, breakGlassUserIds)")
	fixturePath := fs.String("fixture", "", "synthetic tenant fixture")
	auditPath := fs.String("audit", "", "audit log (created if missing, verified before use)")
	approver := fs.String("approver", "", "approver id")
	keyPath := fs.String("key", defKey, "approver private key")
	pubPath := fs.String("pub", defPub, "trusted approver public key")
	faultName := fs.String("fault", "", "inject a mock fault into the first write: write-error, drop-write, concurrent-modify, stale-read")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *cfgPath == "" || *fixturePath == "" || *auditPath == "" || *approver == "" {
		usage(e.stderr)
		return exitUsage
	}
	fault, ok := faults[*faultName]
	if !ok {
		return fail(e, "unknown fault %q", *faultName)
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(e, "%v", err)
	}
	fx, err := mockentra.LoadFixture(*fixturePath)
	if err != nil {
		return fail(e, "%v", err)
	}
	tenant, err := mockentra.New(fx)
	if err != nil {
		return fail(e, "%v", err)
	}
	log, err := audit.Open(*auditPath, e.now)
	if err != nil {
		return fail(e, "%v", err)
	}
	defer log.Close()

	r := runner{e: e, log: log}
	code := r.pipeline(context.Background(), cfg, tenant, fault, *approver, *keyPath, *pubPath)
	if r.err != nil {
		fmt.Fprintf(e.stderr, "kodis: audit: %v\n", r.err)
		return exitError
	}
	fmt.Fprintf(e.stdout, "audit head: %s\n", log.Head())
	return code
}

// runner records every step in the audit log. Any audit failure is
// remembered and turns the run into an error: an unrecorded decision is
// not acceptable.
type runner struct {
	e   env
	log *audit.Log
	err error
}

func (r *runner) record(kind audit.Kind, planHash *model.Digest, data any) bool {
	if r.err != nil {
		return false
	}
	if _, err := r.log.Append(kind, planHash, data); err != nil {
		r.err = err
		return false
	}
	return true
}

func (r *runner) say(format string, args ...any) {
	fmt.Fprintf(r.e.stdout, format+"\n", args...)
}

func (r *runner) pipeline(ctx context.Context, cfg config, tenant *mockentra.Tenant, fault mockentra.Fault, approverID, keyPath, pubPath string) int {
	// Inspect
	snap, err := inspect.Inspect(ctx, tenant.Reader(), cfg.TenantID)
	if !r.record(audit.KindInspect, nil, map[string]any{"tenantId": cfg.TenantID, "policies": len(snap.Policies), "error": errString(err)}) {
		return exitError
	}
	if err != nil {
		return fail(r.e, "%v", err)
	}
	r.say("inspect: %d conditional access policies in %s", len(snap.Policies), snap.TenantID)

	// Evaluate
	findings, err := evaluate.Evaluate(evaluate.Config{BreakGlassUserIDs: cfg.BreakGlassUserIDs}, snap)
	if !r.record(audit.KindEvaluate, nil, map[string]any{"findings": findings, "error": errString(err)}) {
		return exitError
	}
	if err != nil {
		return fail(r.e, "%v", err)
	}
	r.say("evaluate: %d findings", len(findings))
	for _, f := range findings {
		r.say("  [%s] %s %s", f.Severity, f.RuleID, f.Summary)
	}

	// Plan
	now := r.e.now().UTC()
	res, err := plan.Build(plan.Input{
		PlanID:    "plan-" + now.Format("20060102T150405Z"),
		TenantID:  cfg.TenantID,
		CreatedAt: now,
		Snapshot:  snap,
		Findings:  findings,
	})
	var planHash *model.Digest
	if err == nil {
		h, herr := model.HashPlan(res.Plan)
		if herr != nil {
			return fail(r.e, "%v", herr)
		}
		planHash = &h
	}
	if !r.record(audit.KindPlan, planHash, map[string]any{"plan": res.Plan, "skipped": res.Skipped, "error": errString(err)}) {
		return exitError
	}
	for _, s := range res.Skipped {
		r.say("plan: skipped %s: %s", s.FindingID, s.Reason)
	}
	if errors.Is(err, plan.ErrNoActions) {
		r.say("plan: nothing to do")
		return exitNothingToDo
	}
	if err != nil {
		return fail(r.e, "%v", err)
	}
	p := res.Plan

	// Policy
	d := policy.Evaluate(policy.Config{TenantID: cfg.TenantID, BreakGlassUserIDs: cfg.BreakGlassUserIDs}, p, snap)
	if !r.record(audit.KindPolicy, planHash, map[string]any{"allowed": d.Allowed(), "reasons": d.Reasons, "actions": d.Actions}) {
		return exitError
	}
	if !d.Allowed() {
		r.say("policy: DENIED")
		for _, reason := range d.Reasons {
			r.say("  %s: %s", reason.Code, reason.Detail)
		}
		for _, a := range d.Actions {
			for _, reason := range a.Reasons {
				r.say("  %s: %s: %s", a.ActionID, reason.Code, reason.Detail)
			}
		}
		return exitPolicyDenied
	}

	// Approve (human)
	r.say("plan %s (%s)", p.ID, planHash)
	for _, a := range p.Actions {
		r.say("  %s: %s %s/%s %s -> %s (expects version %s)", a.ID, a.Operation, a.Target.Kind, a.Target.ID, a.ExpectedState, a.DesiredState, a.ExpectedVersion)
	}
	r.say("policy: allowed")
	want := strings.TrimPrefix(planHash.String(), "sha256:")[:approvalPrefixLen]
	fmt.Fprintf(r.e.stdout, "To approve as %s, type the first %d hex characters of the plan hash: ", approverID, approvalPrefixLen)
	typed, err := readLine(r.e.stdin)
	r.say("")
	if err != nil || typed != want {
		r.record(audit.KindApproval, planHash, map[string]any{"approved": false, "approverId": approverID})
		r.say("approval: not approved")
		return exitNotApproved
	}
	priv, err := approve.LoadPrivateKey(keyPath)
	if err != nil {
		return fail(r.e, "%v", err)
	}
	pub, err := approve.LoadPublicKey(pubPath)
	if err != nil {
		return fail(r.e, "%v", err)
	}
	signer, err := approve.NewSigner(approverID, priv)
	if err != nil {
		return fail(r.e, "%v", err)
	}
	approval, err := signer.Approve(p, r.e.now(), approvalTTL)
	if err != nil {
		return fail(r.e, "%v", err)
	}
	if !r.record(audit.KindApproval, planHash, map[string]any{"approved": true, "approval": approval}) {
		return exitError
	}
	r.say("approval: signed by %s, expires %s", approverID, approval.Statement.ExpiresAt.Format(time.RFC3339))

	// Execute
	verifier, err := approve.NewVerifier([]approve.TrustedKey{{ApproverID: approverID, PublicKey: pub}})
	if err != nil {
		return fail(r.e, "%v", err)
	}
	x, err := execute.New(execute.Config{
		Policy:   policy.Config{TenantID: cfg.TenantID, BreakGlassUserIDs: cfg.BreakGlassUserIDs},
		Verifier: verifier,
		Reader:   tenant.Reader(),
		Writer:   tenant.Writer(),
		Ledger:   r.log,
		Now:      r.e.now,
	})
	if err != nil {
		return fail(r.e, "%v", err)
	}
	tenant.InjectFault(fault)
	result := x.Execute(ctx, p, approval)
	if !r.record(audit.KindExecute, planHash, result) {
		return exitError
	}
	r.say("execute: %s", result.Status)
	for _, reason := range result.Reasons {
		r.say("  %s", reason)
	}
	for _, s := range result.Steps {
		r.say("  %s: %s %s", s.ActionID, s.Status, s.Err)
	}

	// Verify (always, even after a failed or partial run, to report state)
	rep, err := verify.Verify(ctx, tenant.Reader(), verify.Config{BreakGlassUserIDs: cfg.BreakGlassUserIDs}, p)
	if !r.record(audit.KindVerify, planHash, map[string]any{"verified": rep.Verified(), "checks": rep.Checks, "error": errString(err)}) {
		return exitError
	}
	if err != nil {
		return fail(r.e, "%v", err)
	}
	r.say("verify: verified=%v", rep.Verified())
	for _, c := range rep.Checks {
		for _, pr := range c.Problems {
			r.say("  %s: %s", c.ActionID, pr)
		}
	}
	switch {
	case result.Status != execute.StatusCompleted:
		return exitNotExecuted
	case !rep.Verified():
		return exitNotVerified
	}
	return exitOK
}

// readLine reads one line of at most 256 bytes.
func readLine(r io.Reader) (string, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, 256), 256)
	s, err := br.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func fail(e env, format string, args ...any) int {
	fmt.Fprintf(e.stderr, "kodis: "+format+"\n", args...)
	return exitError
}
