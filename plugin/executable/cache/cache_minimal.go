//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later
package cache

import (
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
)

type cacheBuildState struct{}

func (a *Args) initDumpArgs() {}

func validateCacheArgs(a *Args) error {
	if a.DumpFile != "" || a.DumpInterval != 0 {
		return fmt.Errorf("mosdns_minimal cache does not support dump_file or dump_interval; use the full build")
	}
	return nil
}

func (c *Cache) registerAPI(bp *coremain.BP) {}
func (c *Cache) recordUpdate()               {}
func (c *Cache) initBuildFeatures()          {}
func (c *Cache) closeBuildFeatures()         {}
