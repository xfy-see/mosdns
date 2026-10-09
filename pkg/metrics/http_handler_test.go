//go:build !mosdns_minimal

package metrics

import (
	"compress/gzip"
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHTTPHandlerAndIndependentSnapshots(t *testing.T) {
	r := NewRegistry()
	c := NewCounter(CounterOpts{Name: "requests_total", Help: "requests", ConstLabels: Labels{"tag": "a\"\n\\"}})
	r.MustRegister(c)
	c.Inc()
	families, _ := r.Gather()
	families[0].Metric[0].Label[0].Value = "changed"
	families[0].Metric[0].Counter.Value = 9
	recorder := httptest.NewRecorder()
	HandlerFor(r).ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	if recorder.Code != 200 || recorder.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("HTTP response: %v", recorder)
	}
	if got, want := recorder.Body.String(), text(t, r); got != want || !strings.Contains(got, "requests_total{tag=\"a\\\"\\n\\\\\"} 1\n") {
		t.Fatalf("changed or invalid snapshot: %s", got)
	}
	if !reflect.DeepEqual(c.Descriptor().Labels, Labels{"tag": "a\"\n\\"}) {
		t.Fatal("snapshot mutated collector labels")
	}
}

func TestHTTPGzipTextAndQualityZero(t *testing.T) {
	r := NewRegistry()
	r.MustRegister(NewCounter(CounterOpts{Name: "requests_total"}))
	for _, header := range []string{"gzip", "gzip;q=0", "gzip;q=0, *;q=1"} {
		request := httptest.NewRequest("GET", "/metrics", nil)
		request.Header.Set("Accept-Encoding", header)
		response := httptest.NewRecorder()
		HandlerFor(r).ServeHTTP(response, request)
		got := response.Body.String()
		if header == "gzip" {
			reader, err := gzip.NewReader(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			reader.Close()
			got = string(data)
			if response.Header().Get("Content-Encoding") != "gzip" {
				t.Fatal("gzip not selected")
			}
		} else if response.Header().Get("Content-Encoding") != "" {
			t.Fatal("gzip q=0 ignored")
		}
		if got != text(t, r) {
			t.Fatalf("compressed/plain samples changed: %s", got)
		}
	}
}
