package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Vault owns an exclusive OS file lock. It is a single-host store, not a
// distributed database. Keys and credentials never appear in log messages.
type Vault struct {
	dir  string
	aead cipher.AEAD
	lock *os.File
	// saveHook is a test-only fault injection point, before replacing the file.
	saveHook func(*State) error
}

func DefaultDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		d = "."
	}
	return filepath.Join(d, "galleton")
}
func randomBytes(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err }

func safeRead(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, errors.New("expected a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func createSecret(path string, size int, text bool) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	b, err := randomBytes(size)
	if err != nil {
		return err
	}
	if text {
		b = []byte(base64.RawURLEncoding.EncodeToString(b) + "\n")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
func ensureDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if filepath.Dir(abs) == abs {
		return errors.New("a filesystem root cannot be a private state directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must not be a symlink")
	}
	return os.Chmod(dir, 0700)
}
func Init(dir string) error {
	if err := ensureDir(dir); err != nil {
		return err
	}
	lock, err := lockDirectory(dir)
	if err != nil {
		return err
	}
	defer unlockDirectory(lock)
	if os.Getenv("GALLETON_MASTER_KEY") == "" {
		if err = createSecret(filepath.Join(dir, "master.key"), 32, false); err != nil {
			return err
		}
	} else {
		if _, err = masterKey(dir); err != nil {
			return err
		}
	}
	if err = createSecret(filepath.Join(dir, "api.token"), 32, true); err != nil {
		return err
	}
	configPath := filepath.Join(dir, "adapters.json")
	if _, err = os.Stat(configPath); os.IsNotExist(err) {
		return atomicWrite(configPath, []byte("{\"providers\": []}\n"))
	}
	return err
}
func masterKey(dir string) ([]byte, error) {
	if encoded := os.Getenv("GALLETON_MASTER_KEY"); encoded != "" {
		b, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(b) != 32 {
			return nil, errors.New("GALLETON_MASTER_KEY must be base64 encoding of exactly 32 random bytes")
		}
		return b, nil
	}
	b, err := safeRead(filepath.Join(dir, "master.key"), 32)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("invalid master key file")
	}
	return b, nil
}
func ReadAPIToken(dir string) (string, error) {
	b, err := safeRead(filepath.Join(dir, "api.token"), 256)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid API token file")
	}
	return token, nil
}
func OpenVault(dir string) (*Vault, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	lock, err := lockDirectory(dir)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Vault, error) { unlockDirectory(lock); return nil, err }
	key, err := masterKey(dir)
	if err != nil {
		return fail(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fail(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fail(err)
	}
	return &Vault{dir: dir, aead: aead, lock: lock}, nil
}
func (v *Vault) Close() error {
	if v.lock == nil {
		return nil
	}
	err := unlockDirectory(v.lock)
	v.lock = nil
	return err
}
func (v *Vault) Save(s *State) error {
	if err := checkID(s.ID); err != nil {
		return err
	}
	if v.saveHook != nil {
		if err := v.saveHook(s); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("session state is too large")
	}
	nonce, err := randomBytes(v.aead.NonceSize())
	if err != nil {
		return err
	}
	// Keep the existing on-disk format and authenticated-data namespace stable
	// across the package rename so existing explicit --dir state remains readable.
	blob := append([]byte("SK01"), nonce...)
	blob = v.aead.Seal(blob, nonce, raw, []byte("sessionkit:v1:"+s.ID))
	return atomicWrite(filepath.Join(v.dir, sessionFilename(s.ID)), blob)
}

func sessionFilename(id string) string {
	return "s-" + hex.EncodeToString([]byte(id)) + ".session-v2"
}

func (v *Vault) LoadAll() ([]*State, error) {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return nil, err
	}
	out := []*State{}
	current := map[string]bool{}
	for _, f := range entries {
		if strings.HasSuffix(f.Name(), ".session-v2") {
			encoded := strings.TrimSuffix(strings.TrimPrefix(f.Name(), "s-"), ".session-v2")
			raw, err := hex.DecodeString(encoded)
			id := string(raw)
			if err != nil || checkID(id) != nil || f.Name() != sessionFilename(id) {
				return nil, errors.New("invalid session filename")
			}
			current[id] = true
		}
	}
	type legacyEntry struct { name string; state *State }
	var legacy []legacyEntry
	for _, f := range entries {
		isLegacy := strings.HasSuffix(f.Name(), ".session")
		if !isLegacy && !strings.HasSuffix(f.Name(), ".session-v2") {
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".session")
		if !isLegacy {
			raw, _ := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(f.Name(), "s-"), ".session-v2"))
			id = string(raw)
		}
		if err := checkID(id); err != nil {
			return nil, errors.New("invalid session filename")
		}
		b, err := safeRead(filepath.Join(v.dir, f.Name()), (1<<20)+128)
		if err != nil {
			return nil, err
		}
		n := v.aead.NonceSize()
		if len(b) < 4+n+v.aead.Overhead() || !bytes.Equal(b[:4], []byte("SK01")) {
			return nil, errors.New("invalid encrypted vault entry")
		}
		plain, err := v.aead.Open(nil, b[4:4+n], b[4+n:], []byte("sessionkit:v1:"+id))
		if err != nil {
			return nil, errors.New("vault authentication failed; wrong key or damaged state")
		}
		var s State
		if json.Unmarshal(plain, &s) != nil || s.ID != id {
			return nil, errors.New("invalid vault state")
		}
		if isLegacy {
			legacy = append(legacy, legacyEntry{f.Name(), &s})
		}
		if !isLegacy || !current[id] {
			out = append(out, &s)
		}
		if len(out) > 1024 {
			return nil, errors.New("too many sessions")
		}
	}
	// New-format entries are authoritative after an interrupted migration.
	// Validate every ciphertext before changing any legacy file.
	for _, old := range legacy {
		if !current[old.state.ID] {
			if err := v.Save(old.state); err != nil { return nil, err }
		}
		if err := os.Remove(filepath.Join(v.dir, old.name)); err != nil { return nil, err }
	}
	if len(legacy) > 0 {
		if err := syncDir(v.dir); err != nil { return nil, err }
	}
	return out, nil
}
func (v *Vault) Delete(id string) error {
	if err := checkID(id); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(v.dir, sessionFilename(id))); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(v.dir)
}
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = replaceFile(name, path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return syncDir(dir)
}
