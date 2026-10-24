package approve

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

var now = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

func seed(b byte) *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{b}, 64)) }

func keypair(t *testing.T, b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKey(seed(b))
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testPlan() model.Plan {
	return model.Plan{
		Schema:     model.PlanSchemaV1,
		ID:         "plan-0001",
		TenantID:   "tenant-contoso.example.test",
		CreatedAt:  now.Add(-time.Minute),
		FindingIDs: []string{"finding-0001"},
		Actions: []model.Action{{
			ID:              "action-0001",
			Operation:       model.OpSetConditionalAccessState,
			Target:          model.ResourceRef{Kind: model.KindConditionalAccessPolicy, ID: "ca-require-mfa-admins"},
			ExpectedVersion: "v7",
			ExpectedState:   string(model.CAStateDisabled),
			DesiredState:    string(model.CAStateReportOnly),
		}},
	}
}

type fixture struct {
	signer   *Signer
	verifier *Verifier
	pub      ed25519.PublicKey
}

func setup(t *testing.T) fixture {
	t.Helper()
	pub, priv := keypair(t, 1)
	s, err := NewSigner("alice", priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier([]TrustedKey{{ApproverID: "alice", PublicKey: pub}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{s, v, pub}
}

func approve(t *testing.T, f fixture, p model.Plan) model.Approval {
	t.Helper()
	a, err := f.signer.Approve(p, now, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want approve.Error %s", err, code)
	}
	if e.Code != code {
		t.Fatalf("got %s (%v), want %s", e.Code, err, code)
	}
}

func TestApproveAndVerify(t *testing.T) {
	f := setup(t)
	p := testPlan()
	a := approve(t, f, p)
	if err := f.verifier.Verify(a, p, now); err != nil {
		t.Fatal(err)
	}
	if err := f.verifier.Verify(a, p, now.Add(15*time.Minute-time.Nanosecond)); err != nil {
		t.Fatalf("last valid instant rejected: %v", err)
	}
	// Survives a JSON round trip.
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := model.DecodeApproval(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verifier.Verify(a2, p, now); err != nil {
		t.Fatalf("round-tripped approval rejected: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	f := setup(t)
	p := testPlan()

	otherPub, otherPriv := keypair(t, 2)
	mallory, err := NewSigner("alice", otherPriv) // claims to be alice with an untrusted key
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewSigner("bob", otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	both, err := NewVerifier([]TrustedKey{{ApproverID: "alice", PublicKey: f.pub}, {ApproverID: "bob", PublicKey: otherPub}})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		run  func() error
		want Code
	}{
		{"zero approval", func() error { return f.verifier.Verify(model.Approval{}, p, now) }, CodeInvalid},
		{"no signature", func() error {
			a := approve(t, f, p)
			a.Signature = nil
			return f.verifier.Verify(a, p, now)
		}, CodeInvalid},
		{"truncated signature", func() error {
			a := approve(t, f, p)
			a.Signature = a.Signature[:10]
			return f.verifier.Verify(a, p, now)
		}, CodeBadSignature},
		{"flipped signature bit", func() error {
			a := approve(t, f, p)
			a.Signature[0] ^= 1
			return f.verifier.Verify(a, p, now)
		}, CodeBadSignature},
		{"untrusted key", func() error {
			a, err := mallory.Approve(p, now, time.Minute)
			if err != nil {
				return err
			}
			return f.verifier.Verify(a, p, now)
		}, CodeUnknownKey},
		{"untrusted key relabelled as trusted key id", func() error {
			a, err := mallory.Approve(p, now, time.Minute)
			if err != nil {
				return err
			}
			a.Statement.KeyID = KeyID(f.pub)
			return f.verifier.Verify(a, p, now)
		}, CodeBadSignature},
		{"approver id swapped", func() error {
			a := approve(t, f, p)
			a.Statement.ApproverID = "bob"
			return both.Verify(a, p, now)
		}, CodeApproverMismatch},
		{"bob signs as alice", func() error {
			a, err := bob.Approve(p, now, time.Minute)
			if err != nil {
				return err
			}
			a.Statement.ApproverID = "alice"
			return both.Verify(a, p, now)
		}, CodeApproverMismatch},
		{"plan changed after approval", func() error {
			a := approve(t, f, p)
			q := testPlan()
			q.Actions[0].DesiredState = string(model.CAStateEnabled)
			return f.verifier.Verify(a, q, now)
		}, CodePlanMismatch},
		{"plan hash rewritten", func() error {
			a := approve(t, f, p)
			q := testPlan()
			q.Actions[0].ExpectedVersion = "v8"
			h, err := model.HashPlan(q)
			if err != nil {
				return err
			}
			a.Statement.PlanHash = h
			return f.verifier.Verify(a, q, now)
		}, CodeBadSignature},
		{"invalid plan", func() error {
			a := approve(t, f, p)
			return f.verifier.Verify(a, model.Plan{}, now)
		}, CodePlanMismatch},
		{"expiry extended", func() error {
			a := approve(t, f, p)
			a.Statement.ExpiresAt = a.Statement.ExpiresAt.Add(30 * time.Minute)
			return f.verifier.Verify(a, p, now)
		}, CodeBadSignature},
		{"expired", func() error {
			a := approve(t, f, p)
			return f.verifier.Verify(a, p, now.Add(15*time.Minute))
		}, CodeExpired},
		{"not yet valid", func() error {
			a := approve(t, f, p)
			return f.verifier.Verify(a, p, now.Add(-time.Nanosecond))
		}, CodeNotYetValid},
		{"wrong schema", func() error {
			a := approve(t, f, p)
			a.Statement.Schema = "kodis.approval/v0"
			return f.verifier.Verify(a, p, now)
		}, CodeInvalid},
		{"nil verifier", func() error {
			var v *Verifier
			return v.Verify(approve(t, f, p), p, now)
		}, CodeUnknownKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantCode(t, c.run(), c.want)
		})
	}
}

func TestApproveRejects(t *testing.T) {
	f := setup(t)
	for name, ttl := range map[string]time.Duration{
		"zero ttl":     0,
		"negative ttl": -time.Minute,
		"too long":     model.MaxApprovalTTL + time.Nanosecond,
	} {
		if _, err := f.signer.Approve(testPlan(), now, ttl); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := f.signer.Approve(model.Plan{}, now, time.Minute); err == nil {
		t.Error("approved an invalid plan")
	}
	if _, err := f.signer.Approve(testPlan(), time.Time{}, time.Minute); err == nil {
		t.Error("approved with zero time")
	}
	if _, err := f.signer.Approve(testPlan(), now, model.MaxApprovalTTL); err != nil {
		t.Errorf("max ttl rejected: %v", err)
	}
}

func TestApproverIDValidated(t *testing.T) {
	_, priv := keypair(t, 3)
	s, err := NewSigner("alice smith", priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(testPlan(), now, time.Minute); err == nil {
		t.Fatal("approver id with space accepted")
	}
}

func TestApproveNormalizesTimeToUTC(t *testing.T) {
	f := setup(t)
	jst := now.In(time.FixedZone("JST", 9*3600))
	a, err := f.signer.Approve(testPlan(), jst, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.Statement.IssuedAt.Location() != time.UTC || !a.Statement.IssuedAt.Equal(now) {
		t.Fatalf("issuedAt %v", a.Statement.IssuedAt)
	}
	if err := f.verifier.Verify(a, testPlan(), jst); err != nil {
		t.Fatalf("verify with non-UTC now: %v", err)
	}
}

func TestNewSignerAndVerifierReject(t *testing.T) {
	pub, _ := keypair(t, 4)
	if _, err := NewSigner("alice", ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Error("short private key accepted")
	}
	for name, keys := range map[string][]TrustedKey{
		"none":        nil,
		"short key":   {{ApproverID: "alice", PublicKey: pub[:10]}},
		"no approver": {{PublicKey: pub}},
		"duplicate":   {{ApproverID: "alice", PublicKey: pub}, {ApproverID: "bob", PublicKey: pub}},
	} {
		if _, err := NewVerifier(keys); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestVerifierCopiesKeys(t *testing.T) {
	f := setup(t)
	pub, priv := keypair(t, 5)
	keys := []TrustedKey{{ApproverID: "carol", PublicKey: pub}}
	v, err := NewVerifier(keys)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner("carol", priv)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Approve(testPlan(), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	copy(keys[0].PublicKey, f.pub) // caller mutates its slice afterwards
	if err := v.Verify(a, testPlan(), now); err != nil {
		t.Fatalf("verifier affected by caller mutation: %v", err)
	}
}
