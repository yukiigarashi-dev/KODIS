// Package approve signs and verifies human approvals of plans.
//
// An approval binds one approver key to one exact plan hash for a short
// validity window. Verification fails closed: unknown key, approver
// mismatch, bad signature, different plan, not yet valid or expired are
// all rejections.
//
// Limitation: whoever holds the private key can approve. With a single
// operator holding both the key and the executor, this is not separation
// of duties.
package approve

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// Code identifies why verification failed.
type Code string

const (
	CodeInvalid          Code = "invalid_approval"
	CodeUnknownKey       Code = "unknown_key"
	CodeApproverMismatch Code = "approver_mismatch"
	CodeBadSignature     Code = "bad_signature"
	CodePlanMismatch     Code = "plan_mismatch"
	CodeNotYetValid      Code = "not_yet_valid"
	CodeExpired          Code = "expired"
)

// Error is a verification failure.
type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("approve: %s: %s", e.Code, e.Msg) }

func fail(code Code, format string, args ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// KeyID derives a stable identifier from a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:])
}

// GenerateKey creates a new approver key pair.
func GenerateKey(rand io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}

// Signer approves plans on behalf of one approver.
type Signer struct {
	approverID string
	keyID      string
	priv       ed25519.PrivateKey
}

// NewSigner creates a signer.
func NewSigner(approverID string, priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("approve: private key has %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("approve: cannot derive public key")
	}
	return &Signer{approverID: approverID, keyID: KeyID(pub), priv: priv}, nil
}

// Approve signs an approval of exactly p, valid from now for ttl. It does
// not decide whether p is safe; callers show the policy decision to the
// human before asking for approval.
func (s *Signer) Approve(p model.Plan, now time.Time, ttl time.Duration) (model.Approval, error) {
	h, err := model.HashPlan(p)
	if err != nil {
		return model.Approval{}, fmt.Errorf("approve: %w", err)
	}
	st := model.ApprovalStatement{
		Schema:     model.ApprovalSchemaV1,
		PlanHash:   h,
		ApproverID: s.approverID,
		KeyID:      s.keyID,
		IssuedAt:   now.UTC(),
		ExpiresAt:  now.UTC().Add(ttl),
	}
	msg, err := st.SignedBytes()
	if err != nil {
		return model.Approval{}, fmt.Errorf("approve: %w", err)
	}
	return model.Approval{Statement: st, Signature: ed25519.Sign(s.priv, msg)}, nil
}

// TrustedKey is an approver public key accepted by a Verifier.
type TrustedKey struct {
	ApproverID string
	PublicKey  ed25519.PublicKey
}

type trusted struct {
	approverID string
	pub        ed25519.PublicKey
}

// Verifier checks approvals against a fixed set of trusted keys.
type Verifier struct {
	keys map[string]trusted
}

// NewVerifier creates a verifier. An empty key set is an error: a
// verifier that trusts nobody is a configuration mistake, not a policy.
func NewVerifier(keys []TrustedKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("approve: no trusted keys")
	}
	v := &Verifier{keys: map[string]trusted{}}
	for i, k := range keys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("approve: key %d has %d bytes, want %d", i, len(k.PublicKey), ed25519.PublicKeySize)
		}
		if k.ApproverID == "" {
			return nil, fmt.Errorf("approve: key %d has no approver id", i)
		}
		id := KeyID(k.PublicKey)
		if _, dup := v.keys[id]; dup {
			return nil, fmt.Errorf("approve: duplicate key %s", id)
		}
		v.keys[id] = trusted{approverID: k.ApproverID, pub: append(ed25519.PublicKey(nil), k.PublicKey...)}
	}
	return v, nil
}

// Verify checks that a is a currently valid approval of exactly p.
func (v *Verifier) Verify(a model.Approval, p model.Plan, now time.Time) error {
	if v == nil || len(v.keys) == 0 {
		return fail(CodeUnknownKey, "verifier has no trusted keys")
	}
	if err := a.Validate(); err != nil {
		return fail(CodeInvalid, "%v", err)
	}
	st := a.Statement
	k, ok := v.keys[st.KeyID]
	if !ok {
		return fail(CodeUnknownKey, "key %s is not trusted", st.KeyID)
	}
	if k.approverID != st.ApproverID {
		return fail(CodeApproverMismatch, "key %s belongs to %q, statement names %q", st.KeyID, k.approverID, st.ApproverID)
	}
	msg, err := st.SignedBytes()
	if err != nil {
		return fail(CodeInvalid, "%v", err)
	}
	if len(a.Signature) != ed25519.SignatureSize || !ed25519.Verify(k.pub, msg, a.Signature) {
		return fail(CodeBadSignature, "signature does not verify")
	}
	h, err := model.HashPlan(p)
	if err != nil {
		return fail(CodePlanMismatch, "plan is invalid: %v", err)
	}
	if h != st.PlanHash {
		return fail(CodePlanMismatch, "approval is for %s, plan is %s", st.PlanHash, h)
	}
	if now.Before(st.IssuedAt) {
		return fail(CodeNotYetValid, "issued at %s, now %s", st.IssuedAt, now.UTC())
	}
	if !now.Before(st.ExpiresAt) {
		return fail(CodeExpired, "expired at %s, now %s", st.ExpiresAt, now.UTC())
	}
	return nil
}
