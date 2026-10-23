package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// planHashDomain separates plan hashes from any other SHA-256 use.
const planHashDomain = "kodis.plan/v1\x00"

const digestPrefix = "sha256:"

// Digest is a SHA-256 hash.
type Digest [sha256.Size]byte

func (d Digest) String() string {
	return digestPrefix + hex.EncodeToString(d[:])
}

// ParseDigest parses the form produced by Digest.String. Only lowercase hex
// is accepted so that each digest has exactly one textual form.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	h, ok := strings.CutPrefix(s, digestPrefix)
	if !ok || len(h) != hex.EncodedLen(len(d)) || strings.ToLower(h) != h {
		return Digest{}, invalid("digest", "want %s followed by %d lowercase hex chars", digestPrefix, hex.EncodedLen(len(d)))
	}
	if _, err := hex.Decode(d[:], []byte(h)); err != nil {
		return Digest{}, invalid("digest", "%v", err)
	}
	return d, nil
}

// CanonicalPlan returns the canonical encoding of a valid plan: the
// encoding/json output of the Plan struct. Validate guarantees the inputs
// that would otherwise make this ambiguous (non-UTC times, nil vs empty
// slices, unsorted finding IDs) cannot occur.
func CanonicalPlan(p Plan) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, &Error{Code: CodeMalformed, Msg: err.Error()}
	}
	return b, nil
}

// HashPlan returns the digest an approval is bound to. Invalid plans have
// no hash.
func HashPlan(p Plan) (Digest, error) {
	b, err := CanonicalPlan(p)
	if err != nil {
		return Digest{}, err
	}
	h := sha256.New()
	h.Write([]byte(planHashDomain))
	h.Write(b)
	var d Digest
	h.Sum(d[:0])
	return d, nil
}
