package audit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

const checkpointPrefix = "kodis-ckpt/v1"

// Checkpoint identifies one position in one log: the log ID (hash of its
// init record), a sequence number, and the hash of the record at that
// position. KODIS never stores checkpoints; the operator keeps them
// somewhere the log's writer cannot modify. A checkpoint is only as
// trustworthy as that place.
type Checkpoint struct {
	LogID model.Digest
	Seq   uint64
	Head  model.Digest
}

func hexOf(d model.Digest) string { return strings.TrimPrefix(d.String(), "sha256:") }

// String renders the checkpoint as one copyable line.
func (c Checkpoint) String() string {
	return fmt.Sprintf("%s:%s:%d:%s", checkpointPrefix, hexOf(c.LogID), c.Seq, hexOf(c.Head))
}

// ParseCheckpoint accepts only the exact form produced by String.
func ParseCheckpoint(s string) (Checkpoint, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 || parts[0] != checkpointPrefix {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint must look like %s:<log id>:<seq>:<hash>", checkpointPrefix)
	}
	logID, err := model.ParseDigest("sha256:" + parts[1])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint log id: %w", err)
	}
	head, err := model.ParseDigest("sha256:" + parts[3])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint hash: %w", err)
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || seq == 0 || strconv.FormatUint(seq, 10) != parts[2] {
		return Checkpoint{}, fmt.Errorf("audit: checkpoint seq %q must be a positive decimal without leading zeros", parts[2])
	}
	return Checkpoint{LogID: logID, Seq: seq, Head: head}, nil
}

// ErrCheckpointMismatch means the log does not contain the checkpoint:
// it is a different log, or records at or before the checkpoint were
// removed or altered.
var ErrCheckpointMismatch = errors.New("audit: checkpoint does not match this log")

// Checkpoint returns the checkpoint for the current end of the log.
func (l *Log) Checkpoint() Checkpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Checkpoint{LogID: l.logID, Seq: l.seq, Head: l.head}
}

// VerifyCheckpoint checks that c belongs to this log and that the record
// at c.Seq still has hash c.Head. Together with the chain check done by
// Open, this proves nothing at or before c.Seq was removed or altered.
//
// It cannot detect removal of records written after c was taken.
func (l *Log) VerifyCheckpoint(c Checkpoint) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return verifyCheckpoint(l.logID, l.hashes, c)
}

func verifyCheckpoint(logID model.Digest, hashes []model.Digest, c Checkpoint) error {
	switch {
	case c.LogID != logID:
		return fmt.Errorf("%w: log id is %s, checkpoint is for %s", ErrCheckpointMismatch, hexOf(logID), hexOf(c.LogID))
	case c.Seq == 0 || c.Seq > uint64(len(hashes)):
		return fmt.Errorf("%w: log ends at seq %d, checkpoint is at %d (records were removed)", ErrCheckpointMismatch, len(hashes), c.Seq)
	case hashes[c.Seq-1] != c.Head:
		return fmt.Errorf("%w: record %d hash differs (log was rewritten)", ErrCheckpointMismatch, c.Seq)
	}
	return nil
}

// LogID returns the hash of the init record.
func (l *Log) LogID() model.Digest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logID
}

// TenantID returns the tenant this log is scoped to.
func (l *Log) TenantID() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tenantID
}

// NotBefore returns the time of the latest init or recover record.
// Approvals issued before it must not be executed: claims they could
// have produced may be missing from a log that was truncated and then
// recovered, or replaced by a new one.
func (l *Log) NotBefore() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.notBefore
}

// Recover records an explicit recovery when the operator no longer has a
// valid checkpoint. Records before it are unverified against any
// external anchor. It moves NotBefore to now, invalidating every earlier
// approval. Recovery does not restore claims that may have been removed.
func (l *Log) Recover(reason string) (Record, error) {
	if strings.TrimSpace(reason) == "" {
		return Record{}, errors.New("audit: a recovery reason is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, err := l.appendLocked(KindRecover, nil, map[string]any{
		"reason":            reason,
		"unverifiedThrough": l.seq,
		"previousHead":      l.head,
	})
	if err != nil {
		return Record{}, err
	}
	l.notBefore = rec.Time
	return rec, nil
}
