//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package core

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func lockDirectory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "daemon.lock")
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, errors.New("invalid lock file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("state directory is already locked by another daemon")
	}
	return f, nil
}
func unlockDirectory(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func replaceFile(from, to string) error { return os.Rename(from, to) }
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
