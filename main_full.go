//go:build !mosdns_minimal

package main

import (
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	_ "github.com/IrineSistiana/mosdns/v5/tools"
	"github.com/spf13/cobra"
)

func registerVersion(v string) {
	coremain.AddSubCmd(&cobra.Command{Use: "version", Short: "Print out version info and exit.", Run: func(*cobra.Command, []string) { fmt.Println(v) }})
}
