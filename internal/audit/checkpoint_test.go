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
