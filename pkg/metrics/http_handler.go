//go:build !mosdns_minimal

package metrics

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
)

func HandlerFor(r *Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		families, err := r.Gather()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var b bytes.Buffer
		for _, family := range families {
			if _, err := MetricFamilyToText(&b, family); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Add("Vary", "Accept-Encoding")
		if acceptsGzip(req.Header.Get("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			_, _ = compressed.Write(b.Bytes())
			_ = compressed.Close()
			return
		}
		_, _ = w.Write(b.Bytes())
	})
}

func acceptsGzip(header string) bool {
	quality, wildcard := -1.0, 0.0
	for _, entry := range strings.Split(header, ",") {
		parts := strings.Split(entry, ";")
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		q := 1.0
		for _, option := range parts[1:] {
			option = strings.TrimSpace(option)
			if strings.HasPrefix(option, "q=") {
				value, err := strconv.ParseFloat(strings.TrimPrefix(option, "q="), 64)
				if err != nil || value < 0 || value > 1 {
					q = 0
				} else {
					q = value
				}
			}
		}
		switch name {
		case "gzip":
			quality = q
		case "*":
			wildcard = q
		}
	}
	if quality >= 0 {
		return quality > 0
	}
	return wildcard > 0
}
