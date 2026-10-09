/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package tools

import (
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
)

func newConvCmd() *cobra.Command {
	var (
		in  string
		out string
	)

	c := &cobra.Command{
		Use:   "conv -i input_cfg -o output_cfg",
		Args:  cobra.NoArgs,
		Short: "Convert configuration file format. Supported extensions: yaml, yml, json",
		Run: func(cmd *cobra.Command, args []string) {
			if err := convCfg(in, out); err != nil {
				mlog.S().Fatal(err)
			}
		},
		DisableFlagsInUseLine: true,
	}
	c.Flags().StringVarP(&in, "in", "i", "", "input config")
	c.Flags().StringVarP(&out, "out", "o", "", "output config")
	c.MarkFlagRequired("in")
	c.MarkFlagRequired("out")
	c.MarkFlagFilename("in")
	c.MarkFlagFilename("out")
	return c
}

func newGenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "gen config_file",
		Short: "Generate a template config. Supported extensions: yaml, yml, json",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := genCfg(args[0]); err != nil {
				mlog.S().Fatal(err)
			}
		},
		DisableFlagsInUseLine: true,
	}
	return c
}

func convCfg(in, out string) error {
	values, err := utils.ReadConfigMap(in)
	if err != nil {
		return err
	}
	return writeConfigMap(out, values, "", false)
}

func genCfg(out string) error {
	cfg := `
log:
  level: info

plugins:
  - tag: forward_google
    type: forward
    args:
      upstreams:
        - addr: https://8.8.8.8/dns-query

  - tag: udp_server
    type: udp_server
    args:
      entry: forward_google
      listen: "127.0.0.1:53"
  - tag: tcp_server
    type: tcp_server
    args:
      entry: forward_google
      listen: "127.0.0.1:53"
`
	values, err := utils.DecodeConfigMap([]byte(cfg), "yaml")
	if err != nil {
		return err
	}

	return writeConfigMap(out, values, "yaml", true)
}

func writeConfigMap(out string, values map[string]any, defaultFormat string, overwrite bool) error {
	format := strings.TrimPrefix(filepath.Ext(out), ".")
	if format == "" {
		format = defaultFormat
	}
	data, err := utils.EncodeConfigMap(values, format)
	if err != nil {
		return err
	}
	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	if !overwrite {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(out, flags, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
