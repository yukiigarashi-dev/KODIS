package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/audit"
)

var update = flag.Bool("update", false, "rewrite golden files")

var fixedNow = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

func scenario(name, file string) string {
	return filepath.Join("..", "..", "testdata", "scenarios", name, file)
}

type world struct {
	dir, key, pub, log string
}

func newWorld(t *testing.T) world {
	t.Helper()
	dir := t.TempDir()
	w := world{dir: dir, key: filepath.Join(dir, "approver.key"), pub: filepath.Join(dir, "approver.pub"), log: filepath.Join(dir, "audit.jsonl")}
	code, out, errOut := w.exec(t, "", "keygen", "-key", w.key, "-pub", w.pub)
	if code != exitOK {
		t.Fatalf("keygen: %d %s %s", code, out, errOut)
	}
	return w
}

func (w world) exec(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, env{
		stdin:  strings.NewReader(stdin),
		stdout: &out,
		stderr: &errOut,
		now:    func() time.Time { return fixedNow },
		rand:   bytes.NewReader(bytes.Repeat([]byte{42}, 64)),
	})
	return code, out.String(), errOut.String()
}

func (w world) run(t *testing.T, scen, stdin string, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"run",
		"-config", scenario(scen, "config.json"),
		"-fixture", scenario(scen, "tenant.json"),
		"-audit", w.log,
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
	w := newWorld(t)
	code, out, errOut := w.run(t, "baseline", in)
	if code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	golden(t, "baseline.stdout.golden", out)
	raw, recs := readLog(t, w.log)
	golden(t, "baseline.audit.golden", raw)
	if got := kinds(recs); got != "inspect,evaluate,plan,policy,approval,claim,execute,verify" {
		t.Fatalf("audit kinds %s", got)
	}

	code, out, _ = w.exec(t, "", "audit-verify", "-audit", w.log)
	if code != exitOK || !strings.Contains(out, "8 records, head "+recs[7].Hash.String()) {
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
			"inspect,evaluate,plan,policy,approval", "not approved"},
		{"no approval input", "baseline", "", nil, exitNotApproved,
			"inspect,evaluate,plan,policy,approval", "not approved"},
		{"approval with y", "baseline", "y\n", nil, exitNotApproved,
			"inspect,evaluate,plan,policy,approval", "not approved"},
		{"break-glass not excluded", "breakglass-not-excluded", baselineIn, nil, exitNothingToDo,
			"inspect,evaluate,plan", "nothing to do"},
		{"write dropped is caught by verify", "baseline", baselineIn, []string{"-fault", "drop-write"}, exitNotVerified,
			"inspect,evaluate,plan,policy,approval,claim,execute,verify", "state is \"disabled\""},
		{"stale read is caught by verify", "baseline", baselineIn, []string{"-fault", "stale-read"}, exitNotVerified,
			"inspect,evaluate,plan,policy,approval,claim,execute,verify", "no write is visible"},
		{"concurrent modification", "baseline", baselineIn, []string{"-fault", "concurrent-modify"}, exitNotExecuted,
			"inspect,evaluate,plan,policy,approval,claim,execute,verify", "execute: failed"},
		{"write error", "baseline", baselineIn, []string{"-fault", "write-error"}, exitNotExecuted,
			"inspect,evaluate,plan,policy,approval,claim,execute,verify", "execute: failed"},
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
		"run extra arg":   {"run", "-config", "a", "-fixture", "b", "-audit", "c", "-approver", "d", "extra"},
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
