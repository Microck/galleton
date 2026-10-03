//go:build windows

package core

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var lockFileEx = kernel32.NewProc("LockFileEx")
var unlockFileEx = kernel32.NewProc("UnlockFileEx")
var moveFileEx = kernel32.NewProc("MoveFileExW")

func lockDirectory(dir string) (*os.File, error) {
	path := filepath.Join(dir, "daemon.lock")
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, errors.New("invalid lock file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	ov := syscall.Overlapped{}
	ok, _, _ := lockFileEx.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	if ok == 0 {
		f.Close()
		return nil, errors.New("state directory is already locked by another daemon")
	}
	return f, nil
}
func unlockDirectory(f *os.File) error {
	ov := syscall.Overlapped{}
	unlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	return f.Close()
}
func replaceFile(from, to string) error {
	a, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	b, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	ok, _, callErr := moveFileEx.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)), 9) // REPLACE_EXISTING | WRITE_THROUGH
	if ok == 0 {
		return callErr
	}
	return nil
}
func syncDir(string) error { return nil } // MoveFileExW WRITE_THROUGH; filesystem durability must be validated on Windows.
