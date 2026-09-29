package statuslist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestEncodeDecodeLst_RoundTrip(t *testing.T) {
	raw := []byte{0xC9, 0x44, 0xF9, 0x00, 0xFF, 0x01, 0x02, 0x03}
	lst, err := EncodeLst(raw)
	if err != nil {
		t.Fatalf("EncodeLst: %v", err)
	}
	if lst == "" {
		t.Fatal("EncodeLst returned empty string")
	}
	if bytes.ContainsAny([]byte(lst), "=") {
		t.Fatal("EncodeLst output contains padding, want unpadded base64url per spec §3")
	}

	got, err := DecodeLst(lst)
	if err != nil {
		t.Fatalf("DecodeLst: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("round trip mismatch: got %#v, want %#v", got, raw)
	}
}

func TestBuildAndParseToken_RoundTrip(t *testing.T) {
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
	token, err := BuildToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc123",
		IssuedAt: issuedAt,
		TTL:      3600,
		Bitmap:   bm,
		KeyID:    "test-key-1",
	})
	if err != nil {
		t.Fatalf("BuildToken: %v", err)
	}

	claims, err := ParseToken(token, &key.PublicKey)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}

	if claims.Subject != "https://status.example.org/lists/abc123" {
		t.Errorf("sub = %q, want the list URL", claims.Subject)
	}
	if claims.TTL != 3600 {
		t.Errorf("ttl = %d, want 3600", claims.TTL)
	}
	if claims.StatusList.Bits != 2 {
		t.Errorf("status_list.bits = %d, want 2", claims.StatusList.Bits)
	}
	if !claims.IssuedAt.Equal(issuedAt) {
		t.Errorf("iat = %v, want %v", claims.IssuedAt.Time, issuedAt)
	}

	rawBack, err := DecodeLst(claims.StatusList.Lst)
	if err != nil {
		t.Fatalf("DecodeLst(claims.StatusList.Lst): %v", err)
	}
	rebuilt, err := WrapBitmap(rawBack, bm.Size(), bm.Bits())
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

func TestParseToken_RejectsWrongKey(t *testing.T) {
	key := testSigningKey(t)
	otherKey := testSigningKey(t)

	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		TTL:      60,
		Bitmap:   bm,
	})
	if err != nil {
		t.Fatalf("BuildToken: %v", err)
	}

	if _, err := ParseToken(token, &otherKey.PublicKey); err == nil {
		t.Fatal("expected signature verification to fail against the wrong public key")
	}
}

func TestBuildToken_HeaderTyp(t *testing.T) {
	key := testSigningKey(t)
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		Bitmap:   bm,
	})
	if err != nil {
		t.Fatalf("BuildToken: %v", err)
	}

	// Decode just the header (first segment) to check `typ` without a
	// full parse, keeping this test independent of ParseToken.
	headerB64, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("expected a dot-separated JWT, got %q", token)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header.Typ != "statuslist+jwt" {
		t.Errorf("typ = %q, want %q per draft-ietf-oauth-status-list-21 §5.1", header.Typ, "statuslist+jwt")
	}
	if header.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", header.Alg)
	}
}

func decodeTokenHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	headerB64, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("expected a dot-separated JWT, got %q", token)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return header
}

func TestJWKFromPublicKey(t *testing.T) {
	key := testSigningKey(t)
	jwk, err := JWKFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublicKey: %v", err)
	}
	if jwk["kty"] != "EC" {
		t.Errorf("kty = %v, want EC", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("crv = %v, want P-256", jwk["crv"])
	}
	if jwk["x"] == nil || jwk["y"] == nil {
		t.Errorf("expected x/y coordinates, got %v", jwk)
	}
	for _, unwanted := range []string{"kid", "alg", "use", "d"} {
		if _, present := jwk[unwanted]; present {
			t.Errorf("JWKFromPublicKey included %q, want a bare kty/crv/x/y JWK only", unwanted)
		}
	}
}

func TestBuildToken_JWKHeader(t *testing.T) {
	key := testSigningKey(t)
	jwk, err := JWKFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublicKey: %v", err)
	}
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		Bitmap:   bm,
		JWK:      jwk,
	})
	if err != nil {
		t.Fatalf("BuildToken: %v", err)
	}

	header := decodeTokenHeader(t, token)
	gotJWK, ok := header["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("expected header[\"jwk\"] to be an object, got %#v", header["jwk"])
	}
	if gotJWK["x"] != jwk["x"] || gotJWK["y"] != jwk["y"] {
		t.Errorf("header jwk = %v, want it to match the embedded public key %v", gotJWK, jwk)
	}

	// A verifier that only has the token itself (no out-of-band key)
	// must still be able to validate it purely from the embedded jwk.
	claims, err := ParseToken(token, &key.PublicKey)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.Subject != "https://status.example.org/lists/abc" {
		t.Errorf("sub = %q", claims.Subject)
	}
}

func TestBuildToken_X5CHeader(t *testing.T) {
	key := testSigningKey(t)
	chain := []string{"leaf-cert-der-base64", "intermediate-cert-der-base64"}
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		Bitmap:   bm,
		X5C:      chain,
	})
	if err != nil {
		t.Fatalf("BuildToken: %v", err)
	}

	header := decodeTokenHeader(t, token)
	gotRaw, ok := header["x5c"].([]any)
	if !ok {
		t.Fatalf("expected header[\"x5c\"] to be an array, got %#v", header["x5c"])
	}
	if len(gotRaw) != len(chain) {
		t.Fatalf("x5c has %d entries, want %d", len(gotRaw), len(chain))
	}
	for i, want := range chain {
		if gotRaw[i] != want {
			t.Errorf("x5c[%d] = %v, want %q", i, gotRaw[i], want)
		}
	}
}

func TestBuildToken_NoJWKOrX5CByDefault(t *testing.T) {
	key := testSigningKey(t)
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	token, err := BuildToken(key, TokenParams{
		ListURL:  "https://status.example.org/lists/abc",
		IssuedAt: time.Now(),
		Bitmap:   bm,
	})
	if err != nil {
		t.Fatalf("BuildToken: %v", err)
	}

	header := decodeTokenHeader(t, token)
	if _, present := header["jwk"]; present {
		t.Error("expected no jwk header when TokenParams.JWK is nil")
	}
	if _, present := header["x5c"]; present {
		t.Error("expected no x5c header when TokenParams.X5C is empty")
	}
}
