//go:build !mosdns_minimal

package coremain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSharedPluginAPIMountContract(t *testing.T) {
	data, err := os.ReadFile("../tests/fixtures/plugin_api.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Method, URL, Body string
		Status            int
		Response          *string
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	m := NewTestMosdnsWithPlugins(nil)
	bp := NewBP("echo", m)
	router := chi.NewRouter()
	echo := func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("X-Plugin", bp.Tag())
		fmt.Fprintf(w, "%s|%s|%s|%s", req.Method, req.URL.Path, req.URL.Query().Get("value"), body)
	}
	router.Get("/value", echo)
	router.Post("/value", echo)
	bp.RegAPI(router)
	for _, tc := range cases {
		recorder := httptest.NewRecorder()
		m.httpMux.ServeHTTP(recorder, httptest.NewRequest(tc.Method, tc.URL, strings.NewReader(tc.Body)))
		if recorder.Code != tc.Status {
			t.Fatalf("%s %s: status %d", tc.Method, tc.URL, recorder.Code)
		}
		if tc.Response != nil && (recorder.Body.String() != *tc.Response || recorder.Header().Get("X-Plugin") != "echo") {
			t.Fatalf("%s %s: body=%q header=%q", tc.Method, tc.URL, recorder.Body, recorder.Header().Get("X-Plugin"))
		}
	}
}
