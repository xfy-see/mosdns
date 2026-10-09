//go:build !mosdns_minimal

package coremain

import (
	"bytes"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"net/http"
)

type apiState struct{ httpMux *chi.Mux }

func newAPIState() apiState               { return apiState{httpMux: chi.NewRouter()} }
func validateProfileConfig(*Config) error { return nil }
func (m *Mosdns) initAPI(api APIConfig) error {
	m.apiState = newAPIState()
	m.initHttpMux()
	// Start http api server
	if httpAddr := api.HTTP; len(httpAddr) > 0 {
		httpServer := &http.Server{
			Addr:    httpAddr,
			Handler: m.httpMux,
		}
		m.sc.Attach(func(done func(), closeSignal <-chan struct{}) {
			defer done()
			errChan := make(chan error, 1)
			go func() {
				m.logger.Info("starting api http server", zap.String("addr", httpAddr))
				errChan <- httpServer.ListenAndServe()
			}()
			select {
			case err := <-errChan:
				m.sc.SendCloseSignal(err)
			case <-closeSignal:
				_ = httpServer.Close()
			}
		})
	}

	return nil
}

func (m *Mosdns) GetAPIRouter() *chi.Mux {
	return m.httpMux
}

func (m *Mosdns) RegPluginAPI(tag string, mux *chi.Mux) {
	m.httpMux.Mount("/plugins/"+tag, mux)
}

func newMetricsReg() *metrics.Registry {
	reg := metrics.NewRegistry()
	metrics.RegisterDefaults(reg)
	return reg
}

// initHttpMux initializes api entries. It MUST be called after m.metricsReg being initialized.
func (m *Mosdns) initHttpMux() {
	// Register metrics.
	m.httpMux.Method(http.MethodGet, "/metrics", metrics.HandlerFor(m.metricsReg))

	registerPprof(m.httpMux)

	// A helper page for invalid request.
	invalidApiReqHelper := func(w http.ResponseWriter, req *http.Request) {
		b := new(bytes.Buffer)
		_, _ = fmt.Fprintf(b, "Invalid request %s %s\n\n", req.Method, req.RequestURI)
		b.WriteString("Available api urls:\n")
		_ = chi.Walk(m.httpMux, func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
			b.WriteString(method)
			b.WriteByte(' ')
			b.WriteString(route)
			b.WriteByte('\n')
			return nil
		})
		_, _ = w.Write(b.Bytes())
	}
	m.httpMux.NotFound(invalidApiReqHelper)
	m.httpMux.MethodNotAllowed(invalidApiReqHelper)
}

func (p *BP) RegAPI(mux *chi.Mux) { p.m.RegPluginAPI(p.tag, mux) }
