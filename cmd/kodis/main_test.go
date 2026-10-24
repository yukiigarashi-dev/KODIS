package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/audit"
	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
)

var update = flag.Bool("update", false, "rewrite golden files")

var fixedNow = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

func scenario(name, file string) string {
	return filepath.Join("..", "..", "testdata", "scenarios", name, file)
}

type world struct {
	dir, key, pub, log string
	// ckpt is the latest checkpoint printed by kodis, as an operator would
	// keep it outside the log.
	ckpt string
	// seed makes this world's randomness (keys, log nonces) distinct from
	// every other world's, as crypto/rand would.
	seed [32]byte
	// skew shifts this world's clock relative to fixedNow.
	skew time.Duration
}

var worldCounter atomic.Uint64

func (w *world) rand() io.Reader {
	return bytes.NewReader(append(w.seed[:], w.seed[:]...))
}

var ckptRE = regexp.MustCompile(`(?m)^checkpoint: (kodis-ckpt/v1:\S+)$`)

// newWorld creates keys and an initialized audit log, like an operator
// setting up for the first run.
func newWorld(t *testing.T) *world {
	t.Helper()
	return newSeededWorld(t, sha256.Sum256([]byte(fmt.Sprint("world", worldCounter.Add(1)))))
}

// newSeededWorld fixes the world's randomness, for golden output.
func newSeededWorld(t *testing.T, seed [32]byte) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{dir: dir, key: filepath.Join(dir, "approver.key"), pub: filepath.Join(dir, "approver.pub"), log: filepath.Join(dir, "audit.jsonl"), seed: seed}
	code, out, errOut := w.exec(t, "", "keygen", "-key", w.key, "-pub", w.pub)
	if code != exitOK {
		t.Fatalf("keygen: %d %s %s", code, out, errOut)
	}
	code, out, errOut = w.exec(t, "", "audit-init", "-config", scenario("baseline", "config.json"), "-audit", w.log)
	if code != exitOK || w.ckpt == "" {
		t.Fatalf("audit-init: %d %s %s", code, out, errOut)
	}
	return w
}

func (w *world) exec(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, env{
		stdin:  strings.NewReader(stdin),
		stdout: &out,
		stderr: &errOut,
		now:    func() time.Time { return fixedNow.Add(w.skew) },
		rand:   w.rand(),
	})
	if m := ckptRE.FindAllStringSubmatch(out.String(), -1); m != nil {
		w.ckpt = m[len(m)-1][1]
	}
	return code, out.String(), errOut.String()
}

func (w *world) run(t *testing.T, scen, stdin string, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"run",
		"-config", scenario(scen, "config.json"),
		"-fixture", scenario(scen, "tenant.json"),
		"-audit", w.log,
		"-checkpoint", w.ckpt,
		"-approver", "alice",
		"-key", w.key,
		"-pub", w.pub,
	}, extra...)
	return w.exec(t, stdin, args...)
}

var hashRE = regexp.MustCompile(`\(sha256:([0-9a-f]{64})\)`)

// approvalInput learns the plan hash with a throwaway run (approval
// refused), as a human would by reading the prompt.
func approvalInput(t *testing.T, scen string, extra ...string) string {
	t.Helper()
	w := newWorld(t)
	_, out, _ := w.run(t, scen, "", extra...)
	m := hashRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no plan hash in output:\n%s", out)
	}
	return m[1][:approvalPrefixLen] + "\n"
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func readLog(t *testing.T, path string) (string, []audit.Record) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := audit.Chain(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return string(b), recs
}

func kinds(recs []audit.Record) string {
	var ks []string
	for _, r := range recs {
		ks = append(ks, string(r.Kind))
	}
	return strings.Join(ks, ",")
}

func TestBaselineEndToEnd(t *testing.T) {
	in := approvalInput(t, "baseline")
	var seed [32]byte
	for i := range seed {
		seed[i] = 42
	}
	w := newSeededWorld(t, seed)
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	golden(t, "baseline.stdout.golden", out)
	raw, recs := readLog(t, w.log)
	golden(t, "baseline.audit.golden", raw)
	if got := kinds(recs); got != "init,checkpoint,inspect,evaluate,plan,policy,approval,claim,execute,verify" {
		t.Fatalf("audit kinds %s", got)
	}

	code, out, _ = w.exec(t, "", "audit-verify", "-audit", w.log, "-checkpoint", w.ckpt)
	if code != exitOK || !strings.Contains(out, "10 records") || !strings.Contains(out, "seq 10: verified") {
		t.Fatalf("audit-verify: %d %s", code, out)
	}
}

func TestOutcomes(t *testing.T) {
	baselineIn := approvalInput(t, "baseline")
	cases := []struct {
		name      string
		scenario  string
		stdin     string
		extra     []string
		code      int
		wantKinds string
		wantOut   string
	}{
		{"wrong approval", "baseline", "deadbeefcafe\n", nil, exitNotApproved,
			"init,checkpoint,inspect,evaluate,plan,policy,approval", "not approved"},
		{"no approval input", "baseline", "", nil, exitNotApproved,
			"init,checkpoint,inspect,evaluate,plan,policy,approval", "not approved"},
		{"approval with y", "baseline", "y\n", nil, exitNotApproved,
			"init,checkpoint,inspect,evaluate,plan,policy,approval", "not approved"},
		{"break-glass not excluded", "breakglass-not-excluded", baselineIn, nil, exitNothingToDo,
			"init,checkpoint,inspect,evaluate,plan", "nothing to do"},
		{"write dropped is caught by verify", "baseline", baselineIn, []string{"-fault", "drop-write"}, exitNotVerified,
			"init,checkpoint,inspect,evaluate,plan,policy,approval,claim,execute,verify", "state is \"disabled\""},
		{"stale read is caught by verify", "baseline", baselineIn, []string{"-fault", "stale-read"}, exitNotVerified,
			"init,checkpoint,inspect,evaluate,plan,policy,approval,claim,execute,verify", "no write is visible"},
		{"concurrent modification", "baseline", baselineIn, []string{"-fault", "concurrent-modify"}, exitNotExecuted,
			"init,checkpoint,inspect,evaluate,plan,policy,approval,claim,execute,verify", "execute: failed"},
		{"write error", "baseline", baselineIn, []string{"-fault", "write-error"}, exitNotExecuted,
			"init,checkpoint,inspect,evaluate,plan,policy,approval,claim,execute,verify", "execute: failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			code, out, errOut := w.run(t, c.scenario, c.stdin, c.extra...)
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, c.code, out, errOut)
			}
			if !strings.Contains(out, c.wantOut) {
				t.Fatalf("output lacks %q:\n%s", c.wantOut, out)
			}
			if _, recs := readLog(t, w.log); kinds(recs) != c.wantKinds {
				t.Fatalf("audit kinds %s, want %s", kinds(recs), c.wantKinds)
			}
		})
	}
}

func TestReplayAcrossRunsIsRefused(t *testing.T) {
	in := approvalInput(t, "baseline")
	w := newWorld(t)
	if code, out, errOut := w.run(t, "baseline", in); code != exitOK {
		t.Fatalf("first run %d\n%s\n%s", code, out, errOut)
	}
	// A fresh process with a fresh tenant: only the persisted claim in the
	// audit log can stop the same plan from running again.
	code, out, _ := w.run(t, "baseline", in)
	if code != exitNotExecuted || !strings.Contains(out, "already claimed") {
		t.Fatalf("replay: exit %d\n%s", code, out)
	}
}

func TestTamperedAuditLogStopsRun(t *testing.T) {
	in := approvalInput(t, "baseline")
	w := newWorld(t)
	if code, _, _ := w.run(t, "baseline", "nope\n"); code != exitNotApproved {
		t.Fatal("setup run failed")
	}
	b, err := os.ReadFile(w.log)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.log, bytes.Replace(b, []byte(`"policies":3`), []byte(`"policies":4`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitError || !strings.Contains(errOut, "hash mismatch") || strings.Contains(out, "execute:") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if code, _, _ := w.exec(t, "", "audit-verify", "-audit", w.log); code != exitError {
		t.Fatal("audit-verify accepted a tampered log")
	}
}

func TestInsecureKeyStopsBeforeExecution(t *testing.T) {
	in := approvalInput(t, "baseline")
	w := newWorld(t)
	if err := os.Chmod(w.key, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitError || !strings.Contains(errOut, "permissions") || strings.Contains(out, "execute:") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// Review finding: the failed approval must be in the audit log.
	_, recs := readLog(t, w.log)
	if got := kinds(recs); got != "init,checkpoint,inspect,evaluate,plan,policy,approval" {
		t.Fatalf("audit kinds %s", got)
	}
	data := string(recs[len(recs)-1].Data)
	if !strings.Contains(data, `"approved":false`) || !strings.Contains(data, "permissions") {
		t.Fatalf("approval record %s", data)
	}
}

func TestKeygenNeverOverwrites(t *testing.T) {
	w := newWorld(t)
	before, err := os.ReadFile(w.key)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := w.exec(t, "", "keygen", "-key", w.key, "-pub", w.pub+".2"); code != exitError {
		t.Fatalf("keygen over existing key: exit %d", code)
	}
	after, err := os.ReadFile(w.key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing key modified")
	}
}

func TestUsage(t *testing.T) {
	w := newWorld(t)
	for name, args := range map[string][]string{
		"no args":         nil,
		"unknown command": {"apply"},
		"run no flags":    {"run"},
		"run extra arg":   {"run", "-config", "a", "-fixture", "b", "-audit", "c", "-checkpoint", "x", "-approver", "d", "extra"},
		"run no ckpt":     {"run", "-config", "a", "-fixture", "b", "-audit", "c", "-approver", "d"},
		"init no flags":   {"audit-init"},
		"recover no why":  {"audit-recover", "-audit", "c"},
		"audit no flags":  {"audit-verify"},
		"bad flag":        {"keygen", "-nope"},
	} {
		if code, _, _ := w.exec(t, "", args...); code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, exitUsage)
		}
	}
	if code, _, errOut := w.run(t, "baseline", "", "-fault", "meteor"); code != exitError || !strings.Contains(errOut, "unknown fault") {
		t.Errorf("unknown fault: exit %d %s", code, errOut)
	}
}

// feedFIFO creates a FIFO at path and writes zero bytes into it until
// either the reader closes it or feedCap bytes have been written. It
// returns a function that unblocks and waits for the writer and reports
// how many bytes were accepted. The cap keeps the test safe even if the
// code under test reads without a bound.
func feedFIFO(t *testing.T, path string, feedCap int) func() int {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	written := make(chan int, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			written <- -1
			return
		}
		defer f.Close()
		buf := make([]byte, 64<<10)
		n := 0
		for n < feedCap {
			k, err := f.Write(buf[:min(len(buf), feedCap-n)])
			n += k
			if err != nil {
				break
			}
		}
		written <- n
	}()
	return func() int {
		// If the code under test never opened the FIFO, open the read end
		// ourselves so the writer goroutine can finish.
		if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			r.Close()
		}
		select {
		case n := <-written:
			return n
		case <-time.After(10 * time.Second):
			t.Fatal("FIFO writer did not finish")
			return 0
		}
	}
}

// Review finding: oversized inputs must be rejected without reading them
// whole. The input is a FIFO fed up to 8 MiB; a bounded reader stops after
// about the limit (64 KiB config, 4 MiB fixture) plus pipe buffering.
func TestOversizedStreamsAreRejectedWithoutReadingThem(t *testing.T) {
	const feedCap = 8 << 20
	cases := map[string]struct {
		limit int
		args  func(fifo, log string) []string
	}{
		"config": {maxConfigBytes, func(fifo, log string) []string {
			return []string{"run", "-config", fifo, "-fixture", scenario("baseline", "tenant.json"), "-audit", log, "-checkpoint", "x", "-approver", "alice"}
		}},
		"fixture": {mockentra.MaxFixtureBytes, func(fifo, log string) []string {
			return []string{"run", "-config", scenario("baseline", "config.json"), "-fixture", fifo, "-audit", log, "-checkpoint", "x", "-approver", "alice"}
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			fifo := filepath.Join(w.dir, "input.fifo")
			wait := feedFIFO(t, fifo, feedCap)
			code, _, errOut := w.exec(t, "", c.args(fifo, w.log)...)
			n := wait()
			if code != exitError || !strings.Contains(errOut, "exceeds") {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if n >= feedCap || n > c.limit+(1<<20) {
				t.Fatalf("%d bytes consumed for a %d-byte limit: input was not bounded", n, c.limit)
			}
		})
	}
}

func truncateLog(t *testing.T, path string, keepLines int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	if err := os.WriteFile(path, bytes.Join(lines[:keepLines], nil), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunRequiresInitializedLog(t *testing.T) {
	w := newWorld(t)
	w.log = filepath.Join(w.dir, "never-initialized.jsonl")
	code, out, errOut := w.run(t, "baseline", "")
	if code != exitError || !strings.Contains(errOut, "not initialized") || strings.Contains(out, "inspect:") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if _, err := os.Stat(w.log); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("run created an audit log")
	}
	empty := filepath.Join(w.dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w.log = empty
	if code, _, errOut := w.run(t, "baseline", ""); code != exitError || !strings.Contains(errOut, "not initialized") {
		t.Fatalf("empty log: exit %d %s", code, errOut)
	}
}

func TestBadCheckpointStopsBeforeInspect(t *testing.T) {
	other := newWorld(t)
	other.exec(t, "", "audit-init", "-config", scenario("baseline", "config.json"), "-audit", filepath.Join(other.dir, "second.jsonl"))
	for name, ckpt := range map[string]string{
		"malformed":     "not-a-checkpoint",
		"another log":   other.ckpt,
		"seq too large": "",
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			if ckpt == "" {
				ckpt = strings.Replace(w.ckpt, ":1:", ":9:", 1)
			}
			w.ckpt = ckpt
			code, out, errOut := w.run(t, "baseline", "")
			if code != exitError || strings.Contains(out, "inspect:") {
				t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
			}
			_, recs := readLog(t, w.log)
			if kinds(recs) != "init,checkpoint" || !strings.Contains(string(recs[1].Data), `"ok":false`) {
				t.Fatalf("audit %s %s", kinds(recs), recs[len(recs)-1].Data)
			}
		})
	}
}

func TestLogScopedToAnotherTenantIsRefused(t *testing.T) {
	w := newWorld(t)
	cfg := filepath.Join(w.dir, "other-tenant.json")
	if err := os.WriteFile(cfg, []byte(`{"tenantId":"tenant-other.example.test","breakGlassUserIds":["user-breakglass-01"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w.log = filepath.Join(w.dir, "other.jsonl")
	if code, _, errOut := w.exec(t, "", "audit-init", "-config", cfg, "-audit", w.log); code != exitOK {
		t.Fatalf("init: %s", errOut)
	}
	code, out, errOut := w.run(t, "baseline", "")
	if code != exitError || !strings.Contains(errOut, "scoped to tenant") || strings.Contains(out, "inspect:") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestTruncationBeforeCheckpointIsDetected(t *testing.T) {
	in := approvalInput(t, "baseline")
	w := newWorld(t)
	if code, _, _ := w.run(t, "baseline", in); code != exitOK {
		t.Fatal("first run failed")
	}
	_, recs := readLog(t, w.log)
	truncateLog(t, w.log, len(recs)-4) // drop claim, execute, verify...; chain still verifies
	if code, _, errOut := w.exec(t, "", "audit-verify", "-audit", w.log); code != exitOK {
		t.Fatalf("chain alone should still verify: %s", errOut)
	}
	if code, _, errOut := w.exec(t, "", "audit-verify", "-audit", w.log, "-checkpoint", w.ckpt); code != exitError || !strings.Contains(errOut, "records were removed") {
		t.Fatalf("audit-verify with checkpoint: exit %d %s", code, errOut)
	}
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitError || !strings.Contains(errOut, "records were removed") || strings.Contains(out, "execute:") {
		t.Fatalf("run after truncation: exit %d\n%s\n%s", code, out, errOut)
	}
}

// TestTruncationAfterCheckpointAllowsReexecution documents the residual
// risk: if the operator only kept an older checkpoint, records written
// after it (including the claim) can be removed undetected, and the same
// plan can be executed again under a new human approval.
func TestTruncationAfterCheckpointAllowsReexecution(t *testing.T) {
	in := approvalInput(t, "baseline")
	w := newWorld(t)
	old := w.ckpt // taken right after audit-init
	if code, _, _ := w.run(t, "baseline", in); code != exitOK {
		t.Fatal("first run failed")
	}
	truncateLog(t, w.log, 1)
	w.ckpt = old
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitOK {
		t.Fatalf("expected the known limitation to hold (re-execution succeeds): exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestAuditInitRejects(t *testing.T) {
	w := newWorld(t)
	if code, _, _ := w.exec(t, "", "audit-init", "-config", scenario("baseline", "config.json"), "-audit", w.log); code != exitError {
		t.Error("audit-init overwrote an existing log")
	}
	if code, _, _ := w.exec(t, "", "audit-init", "-config", filepath.Join(w.dir, "missing.json"), "-audit", filepath.Join(w.dir, "n.jsonl")); code != exitError {
		t.Error("audit-init without a valid config succeeded")
	}
}

func TestAuditRecover(t *testing.T) {
	w := newWorld(t)
	lost := w.ckpt
	w.ckpt = ""
	args := []string{"audit-recover", "-audit", w.log, "-reason", "checkpoint store lost"}

	code, out, _ := w.exec(t, "wrong\n", args...)
	if code != exitNotApproved || !strings.Contains(out, "not confirmed") {
		t.Fatalf("unconfirmed recovery: exit %d %s", code, out)
	}
	if _, recs := readLog(t, w.log); kinds(recs) != "init" {
		t.Fatalf("unconfirmed recovery wrote %s", kinds(recs))
	}

	m := regexp.MustCompile(`audit log ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no log id in %s", out)
	}
	code, out, errOut := w.exec(t, m[1][:approvalPrefixLen]+"\n", args...)
	if code != exitOK || w.ckpt == "" || w.ckpt == lost {
		t.Fatalf("recovery: exit %d %s %s", code, out, errOut)
	}
	_, recs := readLog(t, w.log)
	if kinds(recs) != "init,recover" || !strings.Contains(string(recs[1].Data), "checkpoint store lost") {
		t.Fatalf("audit %s", kinds(recs))
	}
	// The new checkpoint works for a normal run.
	in := approvalInput(t, "baseline")
	if code, out, errOut := w.run(t, "baseline", in); code != exitOK {
		t.Fatalf("run after recovery: exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestAuditVerifyWithoutCheckpointSaysSo(t *testing.T) {
	w := newWorld(t)
	code, out, _ := w.exec(t, "", "audit-verify", "-audit", w.log)
	if code != exitOK || !strings.Contains(out, "NOT checked") {
		t.Fatalf("exit %d %s", code, out)
	}
	if code, _, _ := w.exec(t, "", "audit-verify", "-audit", w.log, "-checkpoint", "bogus"); code != exitError {
		t.Fatal("malformed checkpoint accepted")
	}
}

// If the clock is behind the last recovery (for example it was moved
// back), approvals issued "now" predate the recovery and are refused.
func TestApprovalsIssuedBeforeRecoveryAreRefused(t *testing.T) {
	w := newWorld(t)
	w.skew = time.Hour
	_, out, _ := w.exec(t, "x\n", "audit-recover", "-audit", w.log, "-reason", "test")
	id := regexp.MustCompile(`audit log ([0-9a-f]{64})`).FindStringSubmatch(out)[1]
	if code, out, errOut := w.exec(t, id[:approvalPrefixLen]+"\n", "audit-recover", "-audit", w.log, "-reason", "test"); code != exitOK {
		t.Fatalf("recover: %d %s %s", code, out, errOut)
	}
	w.skew = 0
	in := approvalInput(t, "baseline")
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitNotExecuted || !strings.Contains(out, "before the ledger") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
}
