//go:build unix

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

func clock() func() time.Time {
	t := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(time.Second)
		return t
	}
}

func digest(b byte) model.Digest {
	var d model.Digest
	d[0] = b
	return d
}

const tenant = "tenant-contoso.example.test"

// approvedLater is an approval time after every test log's init.
var approvedLater = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func seeded(b byte) *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{b}, 64)) }

// create initializes a new log with a deterministic nonce.
func create(t *testing.T, path string) *Log {
	t.Helper()
	l, err := Init(path, clock(), seeded(7), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func open(t *testing.T, path string) *Log {
	t.Helper()
	l, err := Open(path, clock())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// writeLog creates a log with an init record and three more records and
// returns its path and bytes.
func writeLog(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := create(t, path)
	h := digest(1)
	for _, k := range []Kind{KindPlan, KindPolicy, KindExecute} {
		if _, err := l.Append(k, &h, map[string]string{"kind": string(k), "note": "<&>"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, b
}

func TestAppendAndReopen(t *testing.T) {
	path, b := writeLog(t)
	recs, err := Chain(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 || recs[0].Kind != KindInit || recs[0].Prev != (model.Digest{}) || recs[3].Prev != recs[2].Hash {
		t.Fatalf("records %+v", recs)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", fi.Mode().Perm())
	}

	l := open(t, path)
	defer l.Close()
	if l.Head() != recs[3].Hash || l.LogID() != recs[0].Hash || l.TenantID() != tenant {
		t.Fatal("head not restored")
	}
	r, err := l.Append(KindVerify, nil, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 5 || r.Prev != recs[3].Hash || r.PlanHash != "" {
		t.Fatalf("appended %+v", r.Entry)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	_, b := writeLog(t)
	lines := strings.SplitAfter(string(b), "\n")
	lines = lines[:len(lines)-1] // trailing empty element
	join := func(ls ...string) string { return strings.Join(ls, "") }
	replace := func(old, new string) string {
		if !strings.Contains(string(b), old) {
			t.Fatalf("log lacks %q", old)
		}
		return strings.Replace(string(b), old, new, 1)
	}

	cases := map[string]string{
		"data edited":            replace(`"kind":"policy","note"`, `"kind":"POLICY","note"`),
		"kind edited":            replace(`"kind":"execute","planHash"`, `"kind":"verify","planHash"`),
		"time edited":            replace(`09:00:02Z`, `09:00:09Z`),
		"middle line removed":    join(lines[0], lines[1], lines[3]),
		"init line removed":      join(lines[1], lines[2], lines[3]),
		"lines reordered":        join(lines[0], lines[2], lines[1], lines[3]),
		"line duplicated":        join(lines[0], lines[1], lines[1], lines[2], lines[3]),
		"torn last line":         string(b[:len(b)-5]),
		"no final newline":       string(b[:len(b)-1]),
		"garbage appended":       string(b) + "garbage\n",
		"blank line":             join(lines[0], "\n", lines[1], lines[2], lines[3]),
		"unknown field":          replace(`{"seq":1,`, `{"seq":1,"x":1,`),
		"duplicate key":          replace(`{"seq":1,`, `{"seq":1,"SEQ":1,`),
		"escape changes meaning": replace(`"note":"\u003c\u0026\u003e"`, `"note":"\u003e\u0026\u003c"`),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Chain(strings.NewReader(content)); err == nil {
				t.Fatal("tampering not detected")
			}
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, clock()); err == nil {
				t.Fatal("Open accepted a tampered log")
			}
		})
	}
}

// TestEquivalentReencodingIsAccepted documents that the hash covers the
// meaning of a record, not its exact bytes: encoding/json re-escapes
// "<&>" before hashing, so rewriting \u003c as "<" changes nothing.
func TestEquivalentReencodingIsAccepted(t *testing.T) {
	_, b := writeLog(t)
	esc := `"note":"\u003c\u0026\u003e"`
	if !bytes.Contains(b, []byte(esc)) {
		t.Fatalf("log lacks %s", esc)
	}
	re := bytes.ReplaceAll(b, []byte(esc), []byte(`"note":"<&>"`))
	if _, err := Chain(bytes.NewReader(re)); err != nil {
		t.Fatalf("equivalent re-encoding rejected: %v", err)
	}
}

func TestRecordFromAnotherLogIsDetected(t *testing.T) {
	_, a := writeLog(t)
	// A second log with different data: same seq numbers, valid hashes.
	path := filepath.Join(t.TempDir(), "other.jsonl")
	l, err := Init(path, clock(), seeded(8), tenant)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := l.Append(KindInspect, nil, i); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	la, lb := strings.SplitAfter(string(a), "\n"), strings.SplitAfter(string(b), "\n")
	spliced := la[0] + la[1] + lb[2] + la[3]
	if _, err := Chain(strings.NewReader(spliced)); err == nil || !strings.Contains(err.Error(), "chain broken") {
		t.Fatalf("got %v, want chain broken", err)
	}
}

// craft builds a record with a correct hash, to test validation that the
// hash alone cannot provide.
func craft(t *testing.T, e Entry) string {
	t.Helper()
	h, err := hashEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Record{Entry: e, Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestCorrectlyHashedButInvalidRecords(t *testing.T) {
	base := Entry{Seq: 1, Time: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC), Kind: KindInit, Data: json.RawMessage(`1`)}
	if _, err := Chain(strings.NewReader(craft(t, base))); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, mutate := range map[string]func(*Entry){
		"non-UTC time":  func(e *Entry) { e.Time = e.Time.In(time.FixedZone("JST", 9*3600)) },
		"zero time":     func(e *Entry) { e.Time = time.Time{} },
		"unknown kind":  func(e *Entry) { e.Kind = "bogus" },
		"plan first":    func(e *Entry) { e.Kind = KindPlan },
		"bad plan hash": func(e *Entry) { e.PlanHash = "sha256:XYZ" },
		"seq 2 first":   func(e *Entry) { e.Seq = 2 },
		"seq 0":         func(e *Entry) { e.Seq = 0 },
		"non-zero prev": func(e *Entry) { e.Prev = digest(1) },
	} {
		t.Run(name, func(t *testing.T) {
			e := base
			mutate(&e)
			if _, err := Chain(strings.NewReader(craft(t, e))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestEmptyLog(t *testing.T) {
	recs, err := Chain(strings.NewReader(""))
	if err != nil || len(recs) != 0 {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestOpenRejects(t *testing.T) {
	dir := t.TempDir()
	wide := filepath.Join(dir, "wide.jsonl")
	if err := os.WriteFile(wide, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(wide, clock()); err == nil {
		t.Error("group/other-writable log accepted")
	}
	if _, err := Open(dir, clock()); err == nil {
		t.Error("directory accepted")
	}
	if _, err := Open(filepath.Join(dir, "x.jsonl"), nil); err == nil {
		t.Error("nil clock accepted")
	}
	if _, err := Open(filepath.Join(dir, "missing.jsonl"), clock()); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("missing log: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Error("Open created a log")
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(empty, clock()); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("empty log treated as initialized: %v", err)
	}
}

func TestInitRejects(t *testing.T) {
	path, _ := writeLog(t)
	if _, err := Init(path, clock(), seeded(1), tenant); err == nil {
		t.Error("Init reused an existing log")
	}
	dir := t.TempDir()
	for name, c := range map[string]struct {
		rand   *bytes.Reader
		tenant string
	}{
		"empty tenant":     {seeded(1), ""},
		"tenant w/ space":  {seeded(1), "a b"},
		"short randomness": {bytes.NewReader([]byte{1, 2, 3}), tenant},
	} {
		p := filepath.Join(dir, name+".jsonl")
		if _, err := Init(p, clock(), c.rand, c.tenant); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: left a file behind", name)
		}
	}
}

func TestInitDataIsValidatedOnOpen(t *testing.T) {
	for name, data := range map[string]string{
		"not an object": `1`,
		"no nonce":      `{"tenantId":"t"}`,
		"short nonce":   `{"tenantId":"t","nonce":"abcd"}`,
		"uppercase":     `{"tenantId":"t","nonce":"` + strings.Repeat("AB", 32) + `"}`,
		"unknown field": `{"tenantId":"t","nonce":"` + strings.Repeat("ab", 32) + `","x":1}`,
		"empty tenant":  `{"tenantId":"","nonce":"` + strings.Repeat("ab", 32) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.jsonl")
			e := Entry{Seq: 1, Time: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC), Kind: KindInit, Data: json.RawMessage(data)}
			if err := os.WriteFile(path, []byte(craft(t, e)), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, clock()); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLogIDDependsOnNonce(t *testing.T) {
	dir := t.TempDir()
	ids := map[model.Digest]bool{}
	for i, seed := range []byte{1, 2} {
		l, err := Init(filepath.Join(dir, string(rune('a'+i))+".jsonl"), clock(), seeded(seed), tenant)
		if err != nil {
			t.Fatal(err)
		}
		ids[l.LogID()] = true
		l.Close()
	}
	if len(ids) != 2 {
		t.Fatal("same tenant and clock produced the same log id; a re-created log would match old checkpoints")
	}
}

func TestSecondOpenIsLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := create(t, path)
	if _, err := Open(path, clock()); err == nil {
		t.Fatal("second Open succeeded while locked")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2 := open(t, path)
	l2.Close()
}

func TestAppendRejects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := create(t, path)
	if _, err := l.Append("bogus", nil, 1); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := l.Append(KindInit, nil, 1); err == nil {
		t.Error("second init accepted")
	}
	if _, err := l.Append(KindRecover, nil, 1); err == nil {
		t.Error("recover via Append accepted (would skip NotBefore)")
	}
	if _, err := l.Append(KindPlan, nil, func() {}); err == nil {
		t.Error("unencodable data accepted")
	}
	if _, err := l.Append(KindPlan, nil, strings.Repeat("a", MaxRecordBytes)); err == nil {
		t.Error("oversized record accepted")
	}
	l.Close()
	if _, err := l.Append(KindPlan, nil, 1); err == nil {
		t.Error("append after close accepted")
	}
	// Rejected appends must not have written anything.
	if recs, err := Chain(mustOpen(t, path)); err != nil || len(recs) != 1 {
		t.Fatalf("rejected appends left %d records (%v)", len(recs), err)
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestNonUTCClockIsNormalized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	jst := time.FixedZone("JST", 9*3600)
	l, err := Init(path, func() time.Time { return time.Date(2026, 10, 25, 18, 0, 0, 0, jst) }, seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.Append(KindPlan, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if r.Time.Location() != time.UTC {
		t.Fatal("time not UTC")
	}
	if _, err := Open(path, clock()); err != nil {
		t.Fatalf("reopen: %v", err)
	}
}

func TestClaimPersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := create(t, path)
	if err := l.Claim(digest(7), approvedLater); err != nil {
		t.Fatal(err)
	}
	if err := l.Claim(digest(7), approvedLater); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("second claim: %v", err)
	}
	if err := l.Claim(digest(8), approvedLater); err != nil {
		t.Fatalf("other plan: %v", err)
	}
	l.Close()

	l2 := open(t, path)
	defer l2.Close()
	if err := l2.Claim(digest(7), approvedLater); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("claim after restart: %v", err)
	}
}

func TestConcurrentClaimsExactlyOne(t *testing.T) {
	l := create(t, filepath.Join(t.TempDir(), "audit.jsonl"))
	defer l.Close()
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Claim(digest(9), approvedLater) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d claims succeeded", ok.Load())
	}
}

func TestConcurrentAppendsKeepChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := create(t, path)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(KindInspect, nil, i); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	l.Close()
	recs, err := Chain(mustOpen(t, path))
	if err != nil || len(recs) != 51 {
		t.Fatalf("%d records, %v", len(recs), err)
	}
}
