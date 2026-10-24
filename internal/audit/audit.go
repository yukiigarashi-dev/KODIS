// Package audit is an append-only, hash-chained JSON Lines log of every
// KODIS decision, including denials.
//
// Each record carries the hash of the previous one, so editing, removing
// or reordering records is detected when the log is opened or verified.
// Limitation: someone who can rewrite the whole file can also recompute
// the whole chain. Record the head hash somewhere else (Log.Head) to
// detect that.
//
// One process at a time: Open takes an exclusive lock on the file.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

const (
	recordDomain = "kodis.audit/v1\x00"
	// MaxRecordBytes bounds one line of the log.
	MaxRecordBytes = 1 << 20
)

// Kind is the type of event a record describes.
type Kind string

const (
	KindInspect  Kind = "inspect"
	KindEvaluate Kind = "evaluate"
	KindPlan     Kind = "plan"
	KindPolicy   Kind = "policy"
	KindApproval Kind = "approval"
	KindClaim    Kind = "claim"
	KindExecute  Kind = "execute"
	KindVerify   Kind = "verify"
)

var kinds = []Kind{KindInspect, KindEvaluate, KindPlan, KindPolicy, KindApproval, KindClaim, KindExecute, KindVerify}

// Entry is the hashed part of a record. Field order is part of the hash.
type Entry struct {
	Seq      uint64          `json:"seq"`
	Time     time.Time       `json:"time"`
	Kind     Kind            `json:"kind"`
	PlanHash string          `json:"planHash,omitempty"`
	Data     json.RawMessage `json:"data"`
	Prev     model.Digest    `json:"prev"`
}

// Record is one line of the log.
type Record struct {
	Entry
	Hash model.Digest `json:"hash"`
}

func hashEntry(e Entry) (model.Digest, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return model.Digest{}, err
	}
	h := sha256.New()
	h.Write([]byte(recordDomain))
	h.Write(b)
	var d model.Digest
	h.Sum(d[:0])
	return d, nil
}

func (e Entry) validate() error {
	if !slices.Contains(kinds, e.Kind) {
		return fmt.Errorf("unknown kind %q", e.Kind)
	}
	if e.Time.IsZero() || e.Time.Location() != time.UTC {
		return errors.New("time must be set and UTC")
	}
	if e.PlanHash != "" {
		if _, err := model.ParseDigest(e.PlanHash); err != nil {
			return fmt.Errorf("planHash: %w", err)
		}
	}
	if len(e.Data) == 0 || !json.Valid(e.Data) {
		return errors.New("data must be valid JSON")
	}
	return nil
}

// Chain reads a whole log, checking sequence numbers, links and hashes.
// It returns the records in order.
func Chain(r io.Reader) ([]Record, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var out []Record
	var prev model.Digest
	for line := 1; ; line++ {
		b, err := readLine(br)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", line, err)
		}
		var rec Record
		if err := model.DecodeStrict(b, MaxRecordBytes, &rec); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", line, err)
		}
		if err := rec.validate(); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", line, err)
		}
		if rec.Seq != uint64(line) {
			return nil, fmt.Errorf("audit: line %d: seq %d, want %d", line, rec.Seq, line)
		}
		if rec.Prev != prev {
			return nil, fmt.Errorf("audit: line %d: chain broken (prev %s, want %s)", line, rec.Prev, prev)
		}
		h, err := hashEntry(rec.Entry)
		if err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", line, err)
		}
		if h != rec.Hash {
			return nil, fmt.Errorf("audit: line %d: hash mismatch (record altered)", line)
		}
		out = append(out, rec)
		prev = rec.Hash
	}
}

// readLine returns one newline-terminated line without the newline. A
// final line without a newline is a torn write and is an error.
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		chunk, err := br.ReadSlice('\n')
		buf.Write(chunk)
		if buf.Len() > MaxRecordBytes+1 {
			return nil, fmt.Errorf("record exceeds %d bytes", MaxRecordBytes)
		}
		switch {
		case err == nil:
			return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if buf.Len() == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("last record is not newline-terminated (torn write)")
		default:
			return nil, err
		}
	}
}

// Log is an open audit log.
type Log struct {
	mu      sync.Mutex
	f       *os.File
	now     func() time.Time
	seq     uint64
	head    model.Digest
	claimed map[model.Digest]bool
	closed  bool
}

// Open opens or creates the log at path (mode 0600), verifies the entire
// existing chain and takes an exclusive lock. A broken chain is an error;
// nothing is appended to a log that does not verify.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		return nil, errors.New("audit: clock is required")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
		f.Close()
		return nil, fmt.Errorf("audit: %s must be a regular file not writable by group/other (mode %s)", path, fi.Mode())
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	recs, err := Chain(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l := &Log{f: f, now: now, claimed: map[model.Digest]bool{}}
	for _, r := range recs {
		if r.Kind == KindClaim {
			d, err := model.ParseDigest(r.PlanHash)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s: claim record %d: %w", path, r.Seq, err)
			}
			l.claimed[d] = true
		}
	}
	if n := len(recs); n > 0 {
		l.seq, l.head = recs[n-1].Seq, recs[n-1].Hash
	}
	return l, nil
}

// Head returns the hash of the last record (zero for an empty log).
func (l *Log) Head() model.Digest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Append writes one record and syncs it to disk. planHash may be nil.
func (l *Log) Append(kind Kind, planHash *model.Digest, data any) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(kind, planHash, data)
}

func (l *Log) appendLocked(kind Kind, planHash *model.Digest, data any) (Record, error) {
	if l.closed {
		return Record{}, errors.New("audit: log is closed")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return Record{}, fmt.Errorf("audit: encode data: %w", err)
	}
	e := Entry{Seq: l.seq + 1, Time: l.now().UTC(), Kind: kind, Data: raw, Prev: l.head}
	if planHash != nil {
		e.PlanHash = planHash.String()
	}
	if err := e.validate(); err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	h, err := hashEntry(e)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Entry: e, Hash: h}
	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	if len(line) > MaxRecordBytes {
		return Record{}, fmt.Errorf("audit: record exceeds %d bytes", MaxRecordBytes)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		// The file may now hold a partial line; refuse further writes so
		// the damage is not extended. Open will report the torn record.
		l.closed = true
		return Record{}, fmt.Errorf("audit: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		l.closed = true
		return Record{}, fmt.Errorf("audit: sync: %w", err)
	}
	l.seq, l.head = e.Seq, h
	return rec, nil
}

// ErrAlreadyClaimed means a claim record for the plan already exists.
var ErrAlreadyClaimed = errors.New("audit: plan already claimed")

// Claim records that a plan is about to be executed. Claims persist in
// the log, so a plan cannot be executed twice even across restarts. It
// satisfies execute.Ledger.
func (l *Log) Claim(planHash model.Digest) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.claimed[planHash] {
		return ErrAlreadyClaimed
	}
	if _, err := l.appendLocked(KindClaim, &planHash, struct{}{}); err != nil {
		return err
	}
	l.claimed[planHash] = true
	return nil
}

// Close releases the lock and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return l.f.Close()
}
