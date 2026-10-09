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

package coremain

import (
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/go-viper/mapstructure/v2"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"runtime"
)

type serverFlags struct {
	c         string
	dir       string
	cpu       int
	asService bool
}

func NewServer(sf *serverFlags) (*Mosdns, error) {
	if sf.cpu > 0 {
		runtime.GOMAXPROCS(sf.cpu)
	}

	if len(sf.dir) > 0 {
		err := os.Chdir(sf.dir)
		if err != nil {
			return nil, fmt.Errorf("failed to change the current working directory, %w", err)
		}
		mlog.L().Info("working directory changed", zap.String("path", sf.dir))
	}

	cfg, fileUsed, err := loadConfig(sf.c)
	if err != nil {
		return nil, fmt.Errorf("fail to load config, %w", err)
	}
	mlog.L().Info("main config loaded", zap.String("file", fileUsed))

	return NewMosdns(cfg)
}

// loadConfig reads YAML/YML or JSON. An empty path searches the working
// directory for config.json, config.yaml, then config.yml.
func loadConfig(filePath string) (*Config, string, error) {
	if filePath == "" {
		dir, err := os.Getwd()
		if err != nil {
			return nil, "", fmt.Errorf("failed to read config: %w", err)
		}
		for _, name := range []string{"config.json", "config.yaml", "config.yml"} {
			candidate := filepath.Join(dir, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				filePath = candidate
				break
			}
		}
		if filePath == "" {
			return nil, "", fmt.Errorf("failed to read config: config.json, config.yaml or config.yml not found in %s", dir)
		}
	}

	settings, err := utils.ReadConfigMap(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read config: %w", err)
	}

	cfg := new(Config)
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           cfg,
		ErrorUnused:      true,
		TagName:          "yaml",
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToWeakSliceHookFunc(","),
		),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return cfg, filePath, nil
}
