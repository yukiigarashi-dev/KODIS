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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
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
	// KindInit is always and only the first record. Its hash is the log ID.
	KindInit Kind = "init"
	// KindRecover marks an explicit recovery after a lost checkpoint.
	KindRecover Kind = "recover"
	// KindCheckpoint records the outcome of checking an external checkpoint.
	KindCheckpoint Kind = "checkpoint"
	// KindRecoverRefused records a recovery that was requested but not
	// confirmed. It does not move NotBefore.
	KindRecoverRefused Kind = "recover-refused"
)

var kinds = []Kind{KindInspect, KindEvaluate, KindPlan, KindPolicy, KindApproval, KindClaim, KindExecute, KindVerify, KindInit, KindRecover, KindCheckpoint, KindRecoverRefused}

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
		if (line == 1) != (rec.Kind == KindInit) {
			return nil, fmt.Errorf("audit: line %d: an init record must be first and only first", line)
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
	mu        sync.Mutex
	f         *os.File
	now       func() time.Time
	seq       uint64
	head      model.Digest
	hashes    []model.Digest // hashes[i] is the hash of record seq i+1
	maxTime   time.Time      // latest record time
	logID     model.Digest
	tenantID  string
	notBefore time.Time
	claimed   map[model.Digest]bool
	closed    bool
}

// ErrNotInitialized means the log file is missing or empty. Logs are only
// created by Init, never implicitly.
var ErrNotInitialized = errors.New("audit: log is not initialized (create it explicitly with Init / kodis audit-init)")

type initData struct {
	TenantID string `json:"tenantId"`
	Nonce    string `json:"nonce"`
}

const nonceBytes = 32

// openFile opens path with flags, checks it is a regular file not
// writable by group/other, and takes an exclusive lock.
func openFile(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags, 0o600)
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
	return f, nil
}

// Open opens an existing, initialized log, verifies the entire chain and
// takes an exclusive lock. It never creates a log: a missing or empty file
// is ErrNotInitialized. A broken chain is an error; nothing is appended
// to a log that does not verify.
//
// Verifying the chain does not detect removal of trailing records; check
// an external checkpoint with VerifyCheckpoint for that.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		return nil, errors.New("audit: clock is required")
	}
	f, err := openFile(path, os.O_RDWR|os.O_APPEND)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrNotInitialized)
	}
	if err != nil {
		return nil, err
	}
	recs, err := Chain(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(recs) == 0 {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrNotInitialized)
	}
	l := &Log{f: f, now: now, claimed: map[model.Digest]bool{}}
	if err := l.load(recs); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// Summary is what a verified chain says about itself.
type Summary struct {
	LogID      model.Digest
	TenantID   string
	NotBefore  time.Time
	Checkpoint Checkpoint
	hashes     []model.Digest
	claimed    map[model.Digest]bool
	maxTime    time.Time
}

type recoverData struct {
	Reason            string       `json:"reason"`
	UnverifiedThrough uint64       `json:"unverifiedThrough"`
	PreviousHead      model.Digest `json:"previousHead"`
}

// validateRecover checks that a recover record's data is complete and
// consistent with its position in the chain.
func validateRecover(r Record) error {
	var d recoverData
	if err := model.DecodeStrict(r.Data, MaxRecordBytes, &d); err != nil {
		return err
	}
	switch {
	case strings.TrimSpace(d.Reason) == "":
		return errors.New("reason is empty")
	case d.UnverifiedThrough != r.Seq-1:
		return fmt.Errorf("unverifiedThrough %d, want %d", d.UnverifiedThrough, r.Seq-1)
	case d.PreviousHead != r.Prev:
		return errors.New("previousHead does not match the chain")
	}
	return nil
}

// Summarize validates the init record of a chain returned by Chain and
// summarizes it. It does not touch any file.
func Summarize(recs []Record) (Summary, error) {
	if len(recs) == 0 {
		return Summary{}, ErrNotInitialized
	}
	var d initData
	if err := model.DecodeStrict(recs[0].Data, MaxRecordBytes, &d); err != nil {
		return Summary{}, fmt.Errorf("init record: %w", err)
	}
	if err := d.validate(); err != nil {
		return Summary{}, fmt.Errorf("init record: %w", err)
	}
	sum := Summary{LogID: recs[0].Hash, TenantID: d.TenantID, claimed: map[model.Digest]bool{}}
	for _, r := range recs {
		switch r.Kind {
		case KindClaim:
			h, err := model.ParseDigest(r.PlanHash)
			if err != nil {
				return Summary{}, fmt.Errorf("claim record %d: %w", r.Seq, err)
			}
			sum.claimed[h] = true
		case KindRecover:
			if err := validateRecover(r); err != nil {
				return Summary{}, fmt.Errorf("recover record %d: %w", r.Seq, err)
			}
			fallthrough
		case KindInit:
			// An init or recover record may never be dated before anything
			// already in the log: otherwise an appended record could move
			// NotBefore back and re-admit old approvals.
			if r.Time.Before(sum.maxTime) {
				return Summary{}, fmt.Errorf("%s record %d is dated %s, before earlier record time %s", r.Kind, r.Seq, r.Time, sum.maxTime)
			}
			if r.Time.After(sum.NotBefore) {
				sum.NotBefore = r.Time
			}
		}
		if r.Time.After(sum.maxTime) {
			sum.maxTime = r.Time
		}
		sum.hashes = append(sum.hashes, r.Hash)
	}
	last := recs[len(recs)-1]
	sum.Checkpoint = Checkpoint{LogID: sum.LogID, Seq: last.Seq, Head: last.Hash}
	return sum, nil
}

// VerifyCheckpoint checks c against the summarized chain; see
// Log.VerifyCheckpoint.
func (s Summary) VerifyCheckpoint(c Checkpoint) error {
	return verifyCheckpoint(s.LogID, s.hashes, c)
}

func (l *Log) load(recs []Record) error {
	sum, err := Summarize(recs)
	if err != nil {
		return err
	}
	l.logID, l.tenantID, l.notBefore = sum.LogID, sum.TenantID, sum.NotBefore
	l.hashes, l.claimed, l.maxTime = sum.hashes, sum.claimed, sum.maxTime
	l.seq, l.head = sum.Checkpoint.Seq, sum.Checkpoint.Head
	return nil
}

func (d initData) validate() error {
	if d.TenantID == "" || strings.ContainsAny(d.TenantID, " \t\r\n") {
		return fmt.Errorf("invalid tenantId %q", d.TenantID)
	}
	if len(d.Nonce) != 2*nonceBytes || strings.ToLower(d.Nonce) != d.Nonce {
		return errors.New("nonce must be lowercase hex")
	}
	if _, err := hex.DecodeString(d.Nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	return nil
}

// Init creates a new log at path for one tenant. It refuses to overwrite
// or reuse an existing file. The init record carries a random nonce so a
// log re-created with the same tenant and clock still gets a new log ID.
//
// Init cannot tell a first-ever log from one re-created after deletion;
// re-creation is detected only when the operator compares the new log ID
// with checkpoints they kept.
func Init(path string, now func() time.Time, rand io.Reader, tenantID string) (*Log, error) {
	if now == nil || rand == nil {
		return nil, errors.New("audit: clock and randomness are required")
	}
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, fmt.Errorf("audit: nonce: %w", err)
	}
	d := initData{TenantID: tenantID, Nonce: hex.EncodeToString(nonce)}
	if err := d.validate(); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	f, err := openFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, err
	}
	l := &Log{f: f, now: now, claimed: map[model.Digest]bool{}}
	rec, err := l.Append(KindInit, nil, d)
	if err != nil {
		f.Close()
		return nil, err
	}
	l.tenantID, l.logID, l.notBefore = tenantID, rec.Hash, rec.Time
	return l, nil
}

// Head returns the hash of the last record (zero for an empty log).
func (l *Log) Head() model.Digest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Append writes one record and syncs it to disk. planHash may be nil.
// Init and recover records can only be written by Init and Recover.
func (l *Log) Append(kind Kind, planHash *model.Digest, data any) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if kind == KindRecover || (kind == KindInit) != (l.seq == 0) {
		return Record{}, fmt.Errorf("audit: %q records cannot be appended here", kind)
	}
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
	if (kind == KindRecover || kind == KindInit) && e.Time.Before(l.maxTime) {
		return Record{}, fmt.Errorf("audit: clock is at %s, before the latest record at %s; refusing to date a %s record into the past", e.Time, l.maxTime, kind)
	}
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
	l.hashes = append(l.hashes, h)
	if e.Time.After(l.maxTime) {
		l.maxTime = e.Time
	}
	return rec, nil
}

// ErrAlreadyClaimed means a claim record for the plan already exists.
var ErrAlreadyClaimed = errors.New("audit: plan already claimed")

// ErrApprovalPredatesLedger means the approval was issued before the
// log's last init or recovery, so a claim it produced may be missing.
var ErrApprovalPredatesLedger = errors.New("audit: approval predates the ledger's last init/recovery")

// Claim records that a plan is about to be executed under an approval
// issued at approvalIssuedAt. Claims persist in the log, so a plan cannot
// be executed twice even across restarts. The approval time is checked
// against NotBefore under the same lock as the claim, so a recovery can
// never slip in between. It satisfies execute.Ledger.
func (l *Log) Claim(planHash model.Digest, approvalIssuedAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if approvalIssuedAt.IsZero() || approvalIssuedAt.Before(l.notBefore) {
		return fmt.Errorf("%w: issued at %s, NotBefore %s", ErrApprovalPredatesLedger, approvalIssuedAt.UTC(), l.notBefore)
	}
	if l.claimed[planHash] {
		return ErrAlreadyClaimed
	}
	if _, err := l.appendLocked(KindClaim, &planHash, struct{}{}); err != nil {
		return err
	}
	l.claimed[planHash] = true
	return nil
}

// Guard checks approvalIssuedAt against NotBefore and runs fn while
// holding the log's lock, so Recover cannot interleave with fn and takes
// effect for the next Guard. fn must not call the log (it would
// deadlock). It satisfies execute.Ledger.
func (l *Log) Guard(approvalIssuedAt time.Time, fn func() error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("audit: log is closed")
	}
	if approvalIssuedAt.IsZero() || approvalIssuedAt.Before(l.notBefore) {
		return fmt.Errorf("%w: issued at %s, NotBefore %s", ErrApprovalPredatesLedger, approvalIssuedAt.UTC(), l.notBefore)
	}
	return fn()
}

// Close releases the lock and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return l.f.Close()
}
