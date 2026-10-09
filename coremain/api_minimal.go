//go:build mosdns_minimal

package coremain

import (
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/metrics"
)

type apiState struct{}

func newAPIState() apiState            { return apiState{} }
func newMetricsReg() *metrics.Registry { return metrics.NewRegistry() }
func validateProfileConfig(cfg *Config) error {
	if cfg.API.HTTP != "" {
		return fmt.Errorf("HTTP API is not available in the mosdns_minimal build")
	}
	return nil
}
func (m *Mosdns) initAPI(api APIConfig) error { return validateProfileConfig(&Config{API: api}) }

// Minimal plugins never register HTTP handlers; keep a type-free adapter for
// external plugin source compatibility without importing an HTTP router.
func (p *BP) RegAPI(any)                   {}
func (m *Mosdns) RegPluginAPI(string, any) {}
