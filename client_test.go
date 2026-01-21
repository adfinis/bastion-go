// Copyright (c) Adfinis
// SPDX-License-Identifier: MPL-2.0

package bastion_test

import (
	"os"
	"testing"

	"github.com/adfinis/bastion-go"
	"github.com/stretchr/testify/assert"
)

var testClient *bastion.Client

func TestMain(m *testing.M) {

	cfg := &bastion.Config{
		Host:                  "localhost",
		Port:                  2222,
		Username:              "bastionadmin",
		StrictHostKeyChecking: false,
	}

	var err error
	testClient, err = bastion.New(cfg, bastion.WithPrivateKeyFileAuth(
		"./testdata/id_ed25519",
	))
	if err != nil {
		panic(err)
	}

	code := m.Run()

	os.Exit(code)
}

func TestClientConn(t *testing.T) {
	_, err := testClient.AccountInfo("bastionadmin")
	assert.NoError(t, err)
}

func TestE2ETesting(t *testing.T) {
	t.Run("Create Group", func(t *testing.T) {
		_, err := testClient.CreateGroup("testgroup", "bastionadmin", bastion.ED25519)
		assert.NoError(t, err)
	})

	t.Run("Create Group Access", func(t *testing.T) {
		_, err := testClient.GroupAddServer("testgroup", "192.168.1.10", "*", "*", &bastion.GroupAddServerOptions{Force: true})
		assert.NoError(t, err)
	})

	t.Run("List Group Accesses", func(t *testing.T) {
		groupAccesses, err := testClient.GroupListServers("testgroup")
		assert.NoError(t, err)
		assert.NotNil(t, groupAccesses)
		assert.Greater(t, len(groupAccesses), 0)
	})

	t.Run("List Self Accesses", func(t *testing.T) {
		selfAccesses, err := testClient.SelfListAccesses()
		assert.NoError(t, err)
		assert.NotNil(t, selfAccesses)
		assert.Greater(t, len(selfAccesses), 0)

	})
}
