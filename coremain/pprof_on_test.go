//go:build pprof && !mosdns_minimal

package coremain

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfilingTagRegistersWorkingHandlers(t *testing.T) {
	m := NewTestMosdnsWithPlugins(nil)
	m.initHttpMux()
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine?debug=1", "/debug/pprof/symbol"} {
		w := httptest.NewRecorder()
		m.httpMux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || w.Body.Len() == 0 || strings.HasPrefix(w.Body.String(), "Invalid request ") {
			t.Fatalf("%s: code %d, body %q", path, w.Code, w.Body.String())
		}
	}
}
