//go:build unix

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

func TestCheckpointRoundTrip(t *testing.T) {
	l := create(t, filepath.Join(t.TempDir(), "a.jsonl"))
	defer l.Close()
	c := l.Checkpoint()
	if c.Seq != 1 || c.Head != l.LogID() {
		t.Fatalf("fresh log checkpoint %+v", c)
	}
	got, err := ParseCheckpoint(c.String())
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if !strings.HasPrefix(c.String(), "kodis-ckpt/v1:") {
		t.Fatalf("format %s", c)
	}
}

func TestParseCheckpointRejects(t *testing.T) {
	l := create(t, filepath.Join(t.TempDir(), "a.jsonl"))
	defer l.Close()
	good := l.Checkpoint().String()
	parts := strings.Split(good, ":")
	for name, s := range map[string]string{
		"empty":           "",
		"wrong prefix":    "kodis-ckpt/v2:" + strings.Join(parts[1:], ":"),
		"too few parts":   strings.Join(parts[:3], ":"),
		"too many parts":  good + ":x",
		"seq zero":        strings.Join([]string{parts[0], parts[1], "0", parts[3]}, ":"),
		"seq leading 0":   strings.Join([]string{parts[0], parts[1], "01", parts[3]}, ":"),
		"seq negative":    strings.Join([]string{parts[0], parts[1], "-1", parts[3]}, ":"),
		"seq plus":        strings.Join([]string{parts[0], parts[1], "+1", parts[3]}, ":"),
		"uppercase id":    strings.Join([]string{parts[0], strings.ToUpper(parts[1]), parts[2], parts[3]}, ":"),
		"short hash":      strings.Join([]string{parts[0], parts[1], parts[2], parts[3][:10]}, ":"),
		"with whitespace": " " + good,
	} {
		if _, err := ParseCheckpoint(s); err == nil {
			t.Errorf("%s: accepted %q", name, s)
		}
	}
}

// grow appends n records and returns the checkpoint after each one.
func grow(t *testing.T, l *Log, n int) []Checkpoint {
	t.Helper()
	var out []Checkpoint
	for i := range n {
		if _, err := l.Append(KindInspect, nil, i); err != nil {
			t.Fatal(err)
		}
		out = append(out, l.Checkpoint())
	}
	return out
}

func TestVerifyCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l := create(t, path)
	cps := grow(t, l, 3) // seq 2..4
	l.Close()

	l = open(t, path)
	defer l.Close()
	for _, c := range cps {
		if err := l.VerifyCheckpoint(c); err != nil {
			t.Errorf("checkpoint at seq %d rejected: %v", c.Seq, err)
		}
	}

	// A different log needs a different nonce; with the same nonce and
	// clock two logs are byte-identical (see TestLogIDDependsOnNonce).
	other, err := Init(filepath.Join(t.TempDir(), "b.jsonl"), clock(), seeded(9), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	wrongHead := cps[1]
	wrongHead.Head = cps[2].Head
	beyond := cps[2]
	beyond.Seq++

	for name, c := range map[string]Checkpoint{
		"other log":      other.Checkpoint(),
		"other log id":   {LogID: other.LogID(), Seq: cps[0].Seq, Head: cps[0].Head},
		"wrong head":     wrongHead,
		"beyond log end": beyond,
	} {
		if err := l.VerifyCheckpoint(c); !errors.Is(err, ErrCheckpointMismatch) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func truncateTo(t *testing.T, path string, keepLines int) {
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

func TestTruncationBeforeCheckpointIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l := create(t, path)
	h := digest(3)
	if err := l.Claim(h, approvedLater); err != nil { // seq 2
		t.Fatal(err)
	}
	c := l.Checkpoint()
	l.Close()

	truncateTo(t, path, 1) // remove the claim: the chain alone still verifies
	l = open(t, path)
	defer l.Close()
	if err := l.VerifyCheckpoint(c); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("truncation below the checkpoint not detected: %v", err)
	}
}

// TestTruncationAfterCheckpointIsNotDetected documents the limit of
// checkpoints: records written after the last checkpoint the operator
// kept can be removed without detection, including claims.
func TestTruncationAfterCheckpointIsNotDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l := create(t, path)
	c := l.Checkpoint() // seq 1
	h := digest(4)
	if err := l.Claim(h, approvedLater); err != nil { // seq 2, after the checkpoint
		t.Fatal(err)
	}
	l.Close()

	truncateTo(t, path, 1)
	l = open(t, path)
	defer l.Close()
	if err := l.VerifyCheckpoint(c); err != nil {
		t.Fatalf("expected the old checkpoint to still verify: %v", err)
	}
	if err := l.Claim(h, approvedLater); err != nil {
		t.Fatalf("expected the removed claim to be claimable again (known limit): %v", err)
	}
}

func TestRecreatedLogDoesNotMatchOldCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, err := Init(path, clock(), seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	c := l.Checkpoint()
	l.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Same path, tenant and clock; only the nonce differs.
	l, err = Init(path, clock(), seeded(2), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.VerifyCheckpoint(c); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("re-created log matched the old checkpoint: %v", err)
	}
}

func TestRecover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l := create(t, path)
	initTime := l.NotBefore()
	if initTime.IsZero() {
		t.Fatal("NotBefore not set by init")
	}
	grow(t, l, 2)
	if _, err := l.Recover("  "); err == nil {
		t.Fatal("recovery without a reason accepted")
	}
	rec, err := l.Recover("operator lost checkpoint store")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindRecover || !l.NotBefore().Equal(rec.Time) || !rec.Time.After(initTime) {
		t.Fatalf("recover record %+v, NotBefore %v", rec.Entry, l.NotBefore())
	}
	c := l.Checkpoint()
	l.Close()

	l = open(t, path)
	defer l.Close()
	if !l.NotBefore().Equal(rec.Time) {
		t.Fatalf("NotBefore not restored from log: %v", l.NotBefore())
	}
	if err := l.VerifyCheckpoint(c); err != nil {
		t.Fatalf("post-recovery checkpoint: %v", err)
	}
	if !strings.Contains(string(rec.Data), `"unverifiedThrough":3`) {
		t.Fatalf("recover data %s", rec.Data)
	}
}

func appendCrafted(t *testing.T, path string, e Entry) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(craft(t, e)); err != nil {
		t.Fatal(err)
	}
}

// Review 2 finding 1: a correctly hashed recover record appended after a
// checkpoint must not be able to move NotBefore back, and its data must
// be complete and consistent with the chain.
func TestForgedRecoverRecordsAreRejected(t *testing.T) {
	for name, mk := range map[string]func(prev Record) Entry{
		"dated before init": func(prev Record) Entry {
			return Entry{Seq: 2, Time: prev.Time.Add(-time.Hour), Kind: KindRecover, Prev: prev.Hash,
				Data: json.RawMessage(`{"reason":"x","unverifiedThrough":1,"previousHead":"` + prev.Hash.String() + `"}`)}
		},
		"empty data": func(prev Record) Entry {
			return Entry{Seq: 2, Time: prev.Time.Add(time.Hour), Kind: KindRecover, Prev: prev.Hash, Data: json.RawMessage(`{}`)}
		},
		"blank reason": func(prev Record) Entry {
			return Entry{Seq: 2, Time: prev.Time.Add(time.Hour), Kind: KindRecover, Prev: prev.Hash,
				Data: json.RawMessage(`{"reason":"  ","unverifiedThrough":1,"previousHead":"` + prev.Hash.String() + `"}`)}
		},
		"wrong range": func(prev Record) Entry {
			return Entry{Seq: 2, Time: prev.Time.Add(time.Hour), Kind: KindRecover, Prev: prev.Hash,
				Data: json.RawMessage(`{"reason":"x","unverifiedThrough":7,"previousHead":"` + prev.Hash.String() + `"}`)}
		},
		"wrong previous head": func(prev Record) Entry {
			return Entry{Seq: 2, Time: prev.Time.Add(time.Hour), Kind: KindRecover, Prev: prev.Hash,
				Data: json.RawMessage(`{"reason":"x","unverifiedThrough":1,"previousHead":"` + digest(9).String() + `"}`)}
		},
		"unknown field": func(prev Record) Entry {
			return Entry{Seq: 2, Time: prev.Time.Add(time.Hour), Kind: KindRecover, Prev: prev.Hash,
				Data: json.RawMessage(`{"reason":"x","unverifiedThrough":1,"previousHead":"` + prev.Hash.String() + `","notBefore":"2000-01-01T00:00:00Z"}`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.jsonl")
			l := create(t, path)
			l.Close()
			recs, err := Chain(mustOpen(t, path))
			if err != nil {
				t.Fatal(err)
			}
			appendCrafted(t, path, mk(recs[0]))
			if _, err := Open(path, clock()); err == nil {
				t.Fatal("forged recover record accepted")
			}
		})
	}
}

func TestRecoverRefusesBackwardsClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	l, err := Init(path, func() time.Time { return now }, seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now = now.Add(-time.Minute)
	if _, err := l.Recover("clock went back"); err == nil {
		t.Fatal("recover dated before the latest record accepted")
	}
	if l.NotBefore().Before(time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)) {
		t.Fatal("NotBefore moved back")
	}
}

// Review 2 finding 2: the approval time is checked by the ledger at claim
// time, so a recovery on the same open log takes effect immediately.
func TestClaimRejectsApprovalsBeforeNotBefore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	l, err := Init(path, func() time.Time { return now }, seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	issued := now.Add(time.Minute)

	if err := l.Claim(digest(1), now.Add(-time.Second)); !errors.Is(err, ErrApprovalPredatesLedger) {
		t.Fatalf("approval before init: %v", err)
	}
	if err := l.Claim(digest(1), time.Time{}); !errors.Is(err, ErrApprovalPredatesLedger) {
		t.Fatalf("zero approval time: %v", err)
	}
	now = issued.Add(time.Minute)
	if _, err := l.Recover("lost checkpoint"); err != nil {
		t.Fatal(err)
	}
	if err := l.Claim(digest(1), issued); !errors.Is(err, ErrApprovalPredatesLedger) {
		t.Fatalf("approval before recovery on the same open log: %v", err)
	}
	if err := l.Claim(digest(1), now); err != nil {
		t.Fatalf("approval at the recovery instant: %v", err)
	}
	// Rejected claims wrote nothing.
	if recs, err := Chain(mustOpen(t, path)); err != nil || kindsOf(recs) != "init,recover,claim" {
		t.Fatalf("log %s %v", kindsOf(recs), err)
	}
}

func TestRecoverRefusedDoesNotMoveNotBefore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l := create(t, path)
	before := l.NotBefore()
	if _, err := l.Append(KindRecoverRefused, nil, map[string]string{"reason": "x"}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l = open(t, path)
	defer l.Close()
	if !l.NotBefore().Equal(before) {
		t.Fatal("recover-refused moved NotBefore")
	}
}

func kindsOf(recs []Record) string {
	var ks []string
	for _, r := range recs {
		ks = append(ks, string(r.Kind))
	}
	return strings.Join(ks, ",")
}

// Review 3 finding 1 (ledger side), made deterministic for review 4
// finding 4: fn runs while the log's lock is held (Recover, Claim, Append
// and Close all take it), and the next Guard sees a recovery.
func TestGuardSerializesWithRecover(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	l, err := Init(filepath.Join(t.TempDir(), "a.jsonl"), clk, seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	issued := now.Add(time.Minute)
	now = issued.Add(time.Minute)

	ran := false
	err = l.Guard(issued, func() error {
		ran = true
		if l.mu.TryLock() {
			l.mu.Unlock()
			return errors.New("fn ran without the log's lock held")
		}
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("Guard: %v ran %v", err, ran)
	}
	if _, err := l.Recover("lost checkpoint"); err != nil {
		t.Fatal(err)
	}
	ran = false
	if err := l.Guard(issued, func() error { ran = true; return nil }); !errors.Is(err, ErrApprovalPredatesLedger) || ran {
		t.Fatalf("Guard after recovery: %v ran %v", err, ran)
	}
	if err := l.Guard(time.Time{}, func() error { ran = true; return nil }); !errors.Is(err, ErrApprovalPredatesLedger) || ran {
		t.Fatalf("zero approval time: %v ran %v", err, ran)
	}
	l.Close()
	if err := l.Guard(now, func() error { ran = true; return nil }); err == nil || ran {
		t.Fatalf("Guard on a closed log: %v ran %v", err, ran)
	}
}

// Review 4 finding 4: Recover takes the log's lock, so it cannot run
// inside a guarded write (TestGuardSerializesWithRecover shows fn holds
// it). This cannot fail on correct code: Recover never completes while
// the lock is held. A Recover without the lock completes at once and is
// caught unless it takes longer than the grace period.
func TestRecoverWaitsForTheLock(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	l, err := Init(filepath.Join(t.TempDir(), "a.jsonl"), func() time.Time { return now }, seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	l.mu.Lock()
	go func() {
		_, err := l.Recover("lost checkpoint")
		done <- err
	}()
	select {
	case <-done:
		l.mu.Unlock()
		t.Fatal("Recover completed while the log's lock was held")
	case <-time.After(200 * time.Millisecond):
	}
	l.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Review 4 finding 4: a failing fn releases the lock, its error reaches
// the caller unchanged, and the claim made before it stays, also after
// reopening the log.
func TestGuardErrorKeepsClaim(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, err := Init(path, clk, seeded(1), tenant)
	if err != nil {
		t.Fatal(err)
	}
	h := model.Digest{7}
	issued := now.Add(time.Minute)
	now = issued.Add(time.Minute)
	if err := l.Claim(h, issued); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("write failed")
	if err := l.Guard(issued, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Guard: %v", err)
	}
	if !l.mu.TryLock() {
		t.Fatal("lock still held after fn failed")
	}
	l.mu.Unlock()
	if err := l.Claim(h, issued); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("second claim: %v", err)
	}
	l.Close()
	l = open(t, path)
	defer l.Close()
	if err := l.Claim(h, issued); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("claim after reopen: %v", err)
	}
}

// Review 4 finding 3.
func TestZeroLogRefuses(t *testing.T) {
	var l Log
	ran := false
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	if err := l.Guard(now, func() error { ran = true; return nil }); !errors.Is(err, ErrNotInitialized) || ran {
		t.Fatalf("Guard: %v ran %v", err, ran)
	}
	if err := l.Claim(model.Digest{1}, now); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Claim: %v", err)
	}
}

// Review 3 finding 4: a recover record must not predate any earlier
// record, not just the init record.
func TestRecoverBeforeLaterOrdinaryRecordIsRejected(t *testing.T) {
	t0 := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	initE := Entry{Seq: 1, Time: t0, Kind: KindInit, Data: json.RawMessage(`{"tenantId":"` + tenant + `","nonce":"` + strings.Repeat("ab", 32) + `"}`)}
	h1, err := hashEntry(initE)
	if err != nil {
		t.Fatal(err)
	}
	inspectE := Entry{Seq: 2, Time: t0.Add(2 * time.Hour), Kind: KindInspect, Data: json.RawMessage(`1`), Prev: h1}
	h2, err := hashEntry(inspectE)
	if err != nil {
		t.Fatal(err)
	}
	recoverE := Entry{Seq: 3, Time: t0.Add(time.Hour), Kind: KindRecover, Prev: h2,
		Data: json.RawMessage(`{"reason":"x","unverifiedThrough":2,"previousHead":"` + h2.String() + `"}`)}
	path := filepath.Join(t.TempDir(), "a.jsonl")
	if err := os.WriteFile(path, []byte(craft(t, initE)+craft(t, inspectE)+craft(t, recoverE)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Control: the same log without the out-of-order recover opens.
	ok := filepath.Join(t.TempDir(), "ok.jsonl")
	if err := os.WriteFile(ok, []byte(craft(t, initE)+craft(t, inspectE)), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(ok, clock()); err != nil {
		t.Fatalf("control log rejected: %v", err)
	} else {
		l.Close()
	}
	if _, err := Open(path, clock()); err == nil {
		t.Fatal("recover dated before an earlier inspect record accepted")
	}
}
