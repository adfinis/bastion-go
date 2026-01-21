// Copyright (c) Adfinis
// SPDX-License-Identifier: MPL-2.0

package bastion

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientConn(t *testing.T) {
	cfg := &Config{
		Host:                  "localhost",
		Port:                  2222,
		Username:              "bastionadmin",
		StrictHostKeyChecking: false,
	}

	client, err := New(cfg, WithPrivateKeyFileAuth(
		"./testdata/id_ed25519",
	))
	assert.NoError(t, err)

	_, err = client.AccountInfo("bastionadmin")
	assert.NoError(t, err)
}
