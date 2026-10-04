package core

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// This fixed, synthetic fixture uses the pre-rename encrypted format. Its key,
// nonce, and credential are public test data, never production credentials.
func TestVaultPreRenameFormatCompatibility(t *testing.T) {
	t.Setenv("GALLETON_MASTER_KEY", "")
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(filepath.Join(dir, "master.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString("U0swMQABAgMEBQYHCAkKCzwgv3/n3+Bp6C/25tTEGwXmtewW3FkvDlcRjOF4GyKII3bHhNu0YP1WiF2e/OZcTZ17Wq8os8K+RrUGO2qGk5yVT64lp75NBHJ2kEyc9mCcUO+9CxVOIQ2TnPOpVZbQ9b+NK4OGPPcjJhJlt3q+oThmoC/FkQY=")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rename-check.session"), blob, 0600); err != nil {
		t.Fatal(err)
	}
	vault, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	states, err := vault.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].RefreshToken != "synthetic-rename-fixture" {
		t.Fatal("pre-rename credentials were not preserved")
	}
	states[0].RefreshToken = "synthetic-rotated-fixture"
	if err := vault.Save(states[0]); err != nil {
		t.Fatal(err)
	}
	states, err = vault.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if states[0].RefreshToken != "synthetic-rotated-fixture" {
		t.Fatal("rotated credentials were not readable")
	}
}

func TestGalletonDefaultDirectory(t *testing.T) {
	if filepath.Base(DefaultDir()) != "galleton" {
		t.Fatal("old default directory name")
	}
}

func TestGalletonExternalMasterKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	t.Setenv("GALLETON_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("external master key should not create an on-disk key")
	}
	actual, err := masterKey(dir)
	if err != nil || !bytes.Equal(actual, key) {
		t.Fatal("GALLETON_MASTER_KEY was not read")
	}
	vault, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GALLETON_MASTER_KEY", "not-base64")
	if _, err := masterKey(dir); err == nil {
		t.Fatal("invalid external master key accepted")
	}
}
