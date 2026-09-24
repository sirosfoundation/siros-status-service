package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// issuerIdentity is one synthetic issuer the load test drives traffic
// as: its own EC P-256 keypair and a claimed issuer ID, matching what a
// real issuer would hold. No pre-registration step exists (docs/
// design.md §15.2) — the assertion itself, embedding this key's public
// half, is the whole proof of possession.
type issuerIdentity struct {
	id  string
	key *ecdsa.PrivateKey
}

func newIssuerIdentity(id string) (*issuerIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key for %s: %w", id, err)
	}
	return &issuerIdentity{id: id, key: key}, nil
}

// assertion builds a fresh, short-lived RFC 7523 client assertion for
// one token request. Matches internal/clientassertion's own test
// construction exactly (iss == sub, an embedded jwk header carrying this
// identity's public key, ES256) — see that package's Verify for the
// receiving side this must satisfy.
func (ii *issuerIdentity) assertion(audience string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    ii.id,
		Subject:   ii.id,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	})
	jwk := jose.JSONWebKey{Key: &ii.key.PublicKey}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal jwk for %s: %w", ii.id, err)
	}
	var jwkMap map[string]any
	if err := json.Unmarshal(raw, &jwkMap); err != nil {
		return "", fmt.Errorf("unmarshal jwk for %s: %w", ii.id, err)
	}
	token.Header["jwk"] = jwkMap
	return token.SignedString(ii.key)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// fetchToken exchanges ii's client assertion for an access token at the
// AS's token endpoint (docs/design.md §15.2/15.3) — the same request
// shape internal/as's handleToken expects (form-encoded, not JSON).
func fetchToken(client *http.Client, asURL string, ii *issuerIdentity) (string, error) {
	tokenURL := asURL + "/token"
	asrt, err := ii.assertion(tokenURL)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {asrt},
	}
	resp, err := client.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("token request for %s: %w", ii.id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request for %s: status %d", ii.id, resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response for %s: %w", ii.id, err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token response for %s carried no access_token", ii.id)
	}
	return tr.AccessToken, nil
}
