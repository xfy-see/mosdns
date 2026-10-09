//go:build mosdns_minimal

package main

import "github.com/IrineSistiana/mosdns/v5/coremain"

func registerVersion(v string) { coremain.SetMinimalVersion(v) }
