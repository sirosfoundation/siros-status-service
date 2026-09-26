// Package docs holds this repo's OpenAPI spec and the test that keeps it
// honest — same pattern go-wallet-backend uses for its own
// docs/openapi-admin.yaml (a hand-authored spec, not one generated from
// code annotations, cross-checked against the real registered routes so
// it can't silently drift).
package docs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/accesstoken"
	"github.com/sirosfoundation/siros-status-service/internal/as"
	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/ingestion"
	"github.com/sirosfoundation/siros-status-service/internal/trust"
	"github.com/sirosfoundation/siros-status-service/internal/verifier"
)

func resolveSpecPath() string {
	return filepath.Join(".", "openapi.yaml")
}

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	specPath := resolveSpecPath()
	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Fatalf("OpenAPI spec not found at %s — spec must exist for CI enforcement", specPath)
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("failed to load OpenAPI spec: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("OpenAPI spec validation failed: %v", err)
	}
	return doc
}

// TestOpenAPISpecValid is the same shape as go-wallet-backend's own test of
// the same name: the spec parses, validates, and isn't obviously empty.
func TestOpenAPISpecValid(t *testing.T) {
	doc := loadSpec(t)
	if doc.Info == nil || doc.Info.Title == "" {
		t.Error("spec missing info.title")
	}
	if doc.Paths == nil || doc.Paths.Len() == 0 {
		t.Error("spec has no paths defined")
	}
	t.Logf("OpenAPI spec v%s: %d paths, %d schemas", doc.Info.Version, doc.Paths.Len(), len(doc.Components.Schemas))

	for path := range doc.Paths.Map() {
		if strings.Contains(path, ":") {
			t.Errorf("path %q uses Gin-style :param syntax instead of OpenAPI {param}", path)
		}
	}
}

// buildGinRoutes constructs cmd/as, cmd/ingestion-service, and
// cmd/verifier-service's real Router()s — with nil/throwaway
// dependencies, since only their route *registration* matters here, and
// gin registers a route without ever invoking its handler or touching a
// dependency the handler closure captured. cmd/ingress-router is
// deliberately not included: it's a plain net/http.ServeMux with one
// unbounded reverse-proxy catch-all, not a fixed route table gin's
// Routes() can meaningfully enumerate — its two fixed routes (/healthz,
// /metrics) are covered by TestFixedRoutesDocumented below, and the
// paths it proxies (/allocate, /status/*, /accounting/me) are documented
// here under cmd/ingestion-service, which is where they're actually
// implemented.
func buildGinRoutes(t *testing.T) []gin.RouteInfo {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	km := accesstoken.NewKeyManager(key, "test")

	asSrv := as.New(&config.ASConfig{}, km, trust.AllowAllEvaluator{}, nil)
	ingestionSrv := ingestion.New(&config.IngestionConfig{}, nil, nil, nil, nil, nil)
	verifierSrv := verifier.New(&config.VerifierConfig{}, nil, nil)

	var routes []gin.RouteInfo
	routes = append(routes, asSrv.Router().Routes()...)
	routes = append(routes, ingestionSrv.Router().Routes()...)
	routes = append(routes, verifierSrv.Router().Routes()...)
	return routes
}

// TestOpenAPIRouteCoverage verifies that every gin route registered by
// cmd/as, cmd/ingestion-service, and cmd/verifier-service has a matching
// path+method entry in the spec, and that the spec has no stale entries
// with no matching route — go-wallet-backend's own
// TestAdminOpenAPIRouteCoverage, generalized to this repo's multiple
// gin-based services sharing one combined spec.
func TestOpenAPIRouteCoverage(t *testing.T) {
	doc := loadSpec(t)

	specRoutes := make(map[string]bool)
	specOriginal := make(map[string]string)
	for path, pathItem := range doc.Paths.Map() {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
			if pathItem.GetOperation(method) != nil {
				norm := method + " " + normalizePathParams(path)
				specRoutes[norm] = true
				specOriginal[norm] = method + " " + path
			}
		}
	}

	var missing []string
	registeredNorm := make(map[string]bool)
	for _, route := range buildGinRoutes(t) {
		specPath := ginPathToOpenAPIPath(route.Path)
		norm := route.Method + " " + normalizePathParams(specPath)
		registeredNorm[norm] = true
		if !specRoutes[norm] {
			missing = append(missing, route.Method+" "+specPath)
		}
	}
	// The two fixed ingress-router routes not covered by buildGinRoutes
	// (see its doc comment) — added here so the reverse (stale-docs)
	// check below doesn't flag their spec entries as orphaned.
	for _, fixed := range []string{"GET /healthz", "GET /metrics"} {
		registeredNorm[fixed] = true
	}

	if len(missing) > 0 {
		t.Errorf("routes registered but NOT documented in openapi.yaml:\n  %s\n\nUpdate the spec to include these.", strings.Join(missing, "\n  "))
	}

	var stale []string
	for norm, original := range specOriginal {
		if !registeredNorm[norm] {
			stale = append(stale, original)
		}
	}
	if len(stale) > 0 {
		t.Errorf("spec entries with no matching registered route (stale docs):\n  %s", strings.Join(stale, "\n  "))
	}
}

// TestFixedRoutesDocumented checks cmd/ingress-router's two fixed routes
// directly against its own literal registration in cmd/ingress-router/
// main.go, since it has no gin route table to introspect (see
// buildGinRoutes's doc comment).
func TestFixedRoutesDocumented(t *testing.T) {
	doc := loadSpec(t)
	for _, path := range []string{"/healthz", "/metrics"} {
		item := doc.Paths.Find(path)
		if item == nil || item.Get == nil {
			t.Errorf("GET %s (registered directly in cmd/ingress-router/main.go, and identically on every other binary) is not documented", path)
		}
	}
}

func ginPathToOpenAPIPath(ginPath string) string {
	re := regexp.MustCompile(`:([a-zA-Z_][a-zA-Z0-9_]*)`)
	return re.ReplaceAllString(ginPath, `{$1}`)
}

func normalizePathParams(path string) string {
	re := regexp.MustCompile(`\{[^}]+\}`)
	return re.ReplaceAllString(path, `{_}`)
}
