// Command kodis runs Inspect → Evaluate → Plan → Approve → Execute → Verify
// against a simulated Entra tenant loaded from a synthetic fixture. It has
// no way to connect to a real tenant.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
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
	case "audit-init":
		return cmdAuditInit(args[1:], e)
	case "audit-verify":
		return cmdAuditVerify(args[1:], e)
	case "audit-recover":
		return cmdAuditRecover(args[1:], e)
	default:
		usage(e.stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  kodis keygen [-key PATH] [-pub PATH]
  kodis audit-init -config PATH -audit PATH
  kodis run -config PATH -fixture PATH -audit PATH -checkpoint CKPT -approver ID [-key PATH] [-pub PATH] [-fault NAME]
  kodis audit-verify -audit PATH [-checkpoint CKPT]
  kodis audit-recover -audit PATH -reason TEXT

Every run prints a checkpoint. Keep it somewhere the audit log's writer
cannot modify and pass it to the next run; see docs/audit-checkpoint.md.

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

const checkpointAdvice = "keep this checkpoint outside the audit log's storage; the next run requires it"

func cmdAuditInit(args []string, e env) int {
	fs := flag.NewFlagSet("audit-init", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	cfgPath := fs.String("config", "", "operator config (the log is scoped to its tenantId)")
	path := fs.String("audit", "", "audit log path to create (must not exist)")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *cfgPath == "" || *path == "" {
		return exitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(e, "%v", err)
	}
	log, err := audit.Init(*path, e.now, e.rand, cfg.TenantID)
	if err != nil {
		return fail(e, "%v", err)
	}
	defer log.Close()
	fmt.Fprintf(e.stdout, "audit log created for %s\nlog id: %s\ncheckpoint: %s\n(%s)\n", cfg.TenantID, log.LogID(), log.Checkpoint(), checkpointAdvice)
	return exitOK
}

// cmdAuditVerify is read-only: it takes no lock and appends nothing.
func cmdAuditVerify(args []string, e env) int {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	path := fs.String("audit", "", "audit log path")
	ckpt := fs.String("checkpoint", "", "externally kept checkpoint to verify against")
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
	sum, err := audit.Summarize(recs)
	if err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprintf(e.stdout, "audit log chain OK: %d records, tenant %s\ncurrent checkpoint: %s\n", len(recs), sum.TenantID, sum.Checkpoint)
	if *ckpt == "" {
		fmt.Fprintln(e.stdout, "no external checkpoint given: removal of trailing records is NOT checked")
		return exitOK
	}
	c, err := audit.ParseCheckpoint(*ckpt)
	if err != nil {
		return fail(e, "%v", err)
	}
	if err := sum.VerifyCheckpoint(c); err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprintf(e.stdout, "external checkpoint at seq %d: verified (records after it are not covered)\n", c.Seq)
	return exitOK
}

func cmdAuditRecover(args []string, e env) int {
	fs := flag.NewFlagSet("audit-recover", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	path := fs.String("audit", "", "audit log path")
	reason := fs.String("reason", "", "why no valid checkpoint is available")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *path == "" || strings.TrimSpace(*reason) == "" {
		return exitUsage
	}
	log, err := audit.Open(*path, e.now)
	if err != nil {
		return fail(e, "%v", err)
	}
	defer log.Close()
	id := strings.TrimPrefix(log.LogID().String(), "sha256:")
	fmt.Fprintf(e.stdout, "RECOVERY of audit log %s (tenant %s), currently at %s\n", id, log.TenantID(), log.Checkpoint())
	fmt.Fprintln(e.stdout, "Records up to here will be marked UNVERIFIED: trailing records may already have been removed.")
	fmt.Fprintln(e.stdout, "Every approval issued before now will be refused by the executor.")
	fmt.Fprintf(e.stdout, "To recover, type the first %d hex characters of the log id: ", approvalPrefixLen)
	typed, err := readLine(e.stdin)
	fmt.Fprintln(e.stdout)
	if err != nil || typed != id[:approvalPrefixLen] {
		why := "confirmation did not match the log id"
		if err != nil {
			why = "could not read confirmation: " + err.Error()
		}
		if _, aerr := log.Append(audit.KindRecoverRefused, nil, map[string]string{"reason": *reason, "refused": why}); aerr != nil {
			return fail(e, "audit: %v", aerr)
		}
		fmt.Fprintln(e.stdout, "recovery: not confirmed")
		return exitNotApproved
	}
	if _, err := log.Recover(*reason); err != nil {
		return fail(e, "%v", err)
	}
	fmt.Fprintf(e.stdout, "recovery recorded\ncheckpoint: %s\n(%s)\n", log.Checkpoint(), checkpointAdvice)
	return exitOK
}

// config is operator configuration for one tenant.
type config struct {
	TenantID          string   `json:"tenantId"`
	BreakGlassUserIDs []string `json:"breakGlassUserIds"`
}

func loadConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	b, err := model.ReadLimited(f, maxConfigBytes)
	if err != nil {
		return config{}, fmt.Errorf("%s: %w", path, err)
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
	auditPath := fs.String("audit", "", "audit log created by audit-init (verified before use)")
	ckpt := fs.String("checkpoint", "", "checkpoint printed by the previous run or audit-init (required)")
	approver := fs.String("approver", "", "approver id")
	keyPath := fs.String("key", defKey, "approver private key")
	pubPath := fs.String("pub", defPub, "trusted approver public key")
	faultName := fs.String("fault", "", "inject a mock fault into the first write: write-error, drop-write, concurrent-modify, stale-read")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *cfgPath == "" || *fixturePath == "" || *auditPath == "" || *ckpt == "" || *approver == "" {
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
	code := exitError
	if r.checkLog(*ckpt, cfg.TenantID) {
		code = r.pipeline(context.Background(), cfg, tenant, fault, *approver, *keyPath, *pubPath)
	}
	if r.err != nil {
		fmt.Fprintf(e.stderr, "kodis: audit: %v\n", r.err)
		return exitError
	}
	fmt.Fprintf(e.stdout, "checkpoint: %s\n(%s)\n", log.Checkpoint(), checkpointAdvice)
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

// checkLog verifies the external checkpoint and the log's tenant scope
// before anything else happens, and records the outcome either way.
func (r *runner) checkLog(raw, tenantID string) bool {
	c, err := audit.ParseCheckpoint(raw)
	if err == nil {
		err = r.log.VerifyCheckpoint(c)
	}
	if err == nil && r.log.TenantID() != tenantID {
		err = fmt.Errorf("audit log is scoped to tenant %q, config is for %q", r.log.TenantID(), tenantID)
	}
	if !r.record(audit.KindCheckpoint, nil, map[string]any{"checkpoint": raw, "ok": err == nil, "error": errString(err)}) {
		return false
	}
	if err != nil {
		fail(r.e, "%v", err)
		return false
	}
	r.say("audit: checkpoint seq %d verified; approvals issued before %s are refused", c.Seq, r.log.NotBefore().Format(time.RFC3339))
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
			err = herr
		} else {
			planHash = &h
		}
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
	approval, pub, err := sign(p, approverID, keyPath, pubPath, r.e.now())
	if err != nil {
		// The human said yes but no valid approval exists: record that.
		r.record(audit.KindApproval, planHash, map[string]any{"approved": false, "approverId": approverID, "error": err.Error()})
		return fail(r.e, "%v", err)
	}
	if !r.record(audit.KindApproval, planHash, map[string]any{"approved": true, "approval": approval}) {
		return exitError
	}
	r.say("approval: signed by %s, expires %s", approverID, approval.Statement.ExpiresAt.Format(time.RFC3339))

	// Execute
	verifier, err := approve.NewVerifier([]approve.TrustedKey{{ApproverID: approverID, PublicKey: pub}})
	if err != nil {
		r.record(audit.KindExecute, planHash, map[string]any{"status": "not_started", "error": err.Error()})
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
		r.record(audit.KindExecute, planHash, map[string]any{"status": "not_started", "error": err.Error()})
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

// sign loads the approver keys and signs an approval of p.
func sign(p model.Plan, approverID, keyPath, pubPath string, now time.Time) (model.Approval, ed25519.PublicKey, error) {
	priv, err := approve.LoadPrivateKey(keyPath)
	if err != nil {
		return model.Approval{}, nil, err
	}
	pub, err := approve.LoadPublicKey(pubPath)
	if err != nil {
		return model.Approval{}, nil, err
	}
	signer, err := approve.NewSigner(approverID, priv)
	if err != nil {
		return model.Approval{}, nil, err
	}
	a, err := signer.Approve(p, now, approvalTTL)
	if err != nil {
		return model.Approval{}, nil, err
	}
	return a, pub, nil
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
