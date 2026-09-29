package statuslist

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestBuildAndParseCWTToken_RoundTrip(t *testing.T) {
	key := testSigningKey(t)

	bm, err := NewBitmap(1000, 2)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	if err := bm.Set(42, StatusInvalid); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := bm.Set(7, StatusSuspended); err != nil {
		t.Fatalf("Set: %v", err)
	}

	issuedAt := time.Now().Truncate(time.Second)
	token, err := BuildCWTToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc123",
		IssuedAt: issuedAt,
		TTL:      3600,
		Bitmap:   bm,
		KeyID:    "test-key-1",
	})
	if err != nil {
		t.Fatalf("BuildCWTToken: %v", err)
	}
	if len(token) == 0 {
		t.Fatal("BuildCWTToken returned empty output")
	}

	claims, err := ParseCWTToken(token, &key.PublicKey)
	if err != nil {
		t.Fatalf("ParseCWTToken: %v", err)
	}
	if claims.Subject != "https://status.example.org/lists/abc123" {
		t.Errorf("sub = %q, want the list URL", claims.Subject)
	}
	if claims.TTL != 3600 {
		t.Errorf("ttl = %d, want 3600", claims.TTL)
	}
	if claims.Bits != 2 {
		t.Errorf("bits = %d, want 2", claims.Bits)
	}
	if !claims.IssuedAt.Equal(issuedAt) {
		t.Errorf("iat = %v, want %v", claims.IssuedAt, issuedAt)
	}

	rebuilt, err := WrapBitmap(claims.Lst, bm.Size(), bm.Bits())
	if err != nil {
		t.Fatalf("WrapBitmap: %v", err)
	}
	got42, _ := rebuilt.Get(42)
	if got42 != StatusInvalid {
		t.Errorf("index 42 round-tripped as %v, want StatusInvalid", got42)
	}
	got7, _ := rebuilt.Get(7)
	if got7 != StatusSuspended {
		t.Errorf("index 7 round-tripped as %v, want StatusSuspended", got7)
	}
	got0, _ := rebuilt.Get(0)
	if got0 != StatusValid {
		t.Errorf("untouched index 0 round-tripped as %v, want StatusValid", got0)
	}
}

func TestParseCWTToken_RejectsWrongKey(t *testing.T) {
	key := testSigningKey(t)
	otherKey := testSigningKey(t)

	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildCWTToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		TTL:      60,
		Bitmap:   bm,
	})
	if err != nil {
		t.Fatalf("BuildCWTToken: %v", err)
	}

	if _, err := ParseCWTToken(token, &otherKey.PublicKey); err == nil {
		t.Fatal("expected signature verification to fail against the wrong public key")
	}
}

func TestBuildCWTToken_IsTaggedCOSESign1(t *testing.T) {
	key := testSigningKey(t)
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildCWTToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		Bitmap:   bm,
	})
	if err != nil {
		t.Fatalf("BuildCWTToken: %v", err)
	}

	var tag cbor.RawTag
	if err := cbor.Unmarshal(token, &tag); err != nil {
		t.Fatalf("decode as CBOR tag: %v", err)
	}
	if tag.Number != 18 {
		t.Errorf("tag number = %d, want 18 (COSE_Sign1_Tagged, RFC 9052 §4.2)", tag.Number)
	}

	var parts []cbor.RawMessage
	if err := cbor.Unmarshal(tag.Content, &parts); err != nil {
		t.Fatalf("decode tag content as array: %v", err)
	}
	if len(parts) != 4 {
		t.Fatalf("COSE_Sign1 array has %d elements, want 4 (protected, unprotected, payload, signature)", len(parts))
	}

	var protected map[int]any
	var protectedBytes []byte
	if err := cbor.Unmarshal(parts[0], &protectedBytes); err != nil {
		t.Fatalf("protected header is not a byte string: %v", err)
	}
	if err := cbor.Unmarshal(protectedBytes, &protected); err != nil {
		t.Fatalf("decode protected header map: %v", err)
	}
	algVal, ok := protected[1]
	if !ok {
		t.Fatal("protected header missing alg (label 1)")
	}
	algInt, ok := toInt64(algVal)
	if !ok || algInt != -7 {
		t.Errorf("alg = %v, want -7 (ES256, RFC 9053 §2.1)", algVal)
	}
	typVal, _ := protected[16].(string)
	if typVal != "application/statuslist+cwt" {
		t.Errorf("typ = %q, want application/statuslist+cwt per §5.2", typVal)
	}
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func TestBuildCWTToken_X5Chain(t *testing.T) {
	key := testSigningKey(t)
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}

	// A real (if minimal) DER blob isn't needed here — BuildCWTToken only
	// base64-decodes and re-embeds it; the certificate's own validity is
	// the caller's concern (config.optionalCertChainEnv already validates
	// it's real DER at load time).
	fakeDER := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	chain := []string{base64.StdEncoding.EncodeToString(fakeDER)}

	token, err := BuildCWTToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		Bitmap:   bm,
		X5C:      chain,
	})
	if err != nil {
		t.Fatalf("BuildCWTToken: %v", err)
	}

	var tag cbor.RawTag
	if err := cbor.Unmarshal(token, &tag); err != nil {
		t.Fatalf("decode as CBOR tag: %v", err)
	}
	var parts []cbor.RawMessage
	if err := cbor.Unmarshal(tag.Content, &parts); err != nil {
		t.Fatalf("decode tag content as array: %v", err)
	}
	var protectedBytes []byte
	if err := cbor.Unmarshal(parts[0], &protectedBytes); err != nil {
		t.Fatalf("protected header is not a byte string: %v", err)
	}
	var protected map[int]any
	if err := cbor.Unmarshal(protectedBytes, &protected); err != nil {
		t.Fatalf("decode protected header map: %v", err)
	}
	x5chain, ok := protected[33].([]byte)
	if !ok {
		t.Fatalf("expected protected[33] (x5chain) to be a single byte string for a one-entry chain, got %#v", protected[33])
	}
	if !bytes.Equal(x5chain, fakeDER) {
		t.Errorf("x5chain = %x, want %x", x5chain, fakeDER)
	}
}
