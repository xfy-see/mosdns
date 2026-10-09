//go:build !pprof && !mosdns_minimal

package coremain

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestDefaultBuildDoesNotRegisterProfiling(t *testing.T) {
	m := NewTestMosdnsWithPlugins(nil)
	m.initHttpMux()
	if err := chi.Walk(m.httpMux, func(_ string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/debug/pprof") {
			t.Fatalf("profiling route registered without build tag: %s", route)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	m.httpMux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if !strings.HasPrefix(w.Body.String(), "Invalid request ") {
		t.Fatalf("unexpected profiling response: %s", w.Body.String())
	}
}
