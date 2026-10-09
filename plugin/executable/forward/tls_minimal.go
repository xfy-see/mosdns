//go:build mosdns_minimal

// SPDX-License-Identifier: GPL-3.0-or-later

package fastforward

import (
	"crypto/tls"
	"fmt"
)

func profileTLSConfig(c UpstreamConfig) (*tls.Config, error) {
	if c.InsecureSkipVerify {
		return nil, fmt.Errorf("insecure_skip_verify is unavailable in mosdns_minimal")
	}
	return nil, nil
}
