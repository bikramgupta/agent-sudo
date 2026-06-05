// Package fsutil provides path canonicalization, private-directory and
// permission checks, and content hashing shared across agent-sudo. It depends
// only on the standard library so any package may import it.
package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// EnsurePrivateDir creates the directory (0700) if needed and verifies it is a
// real directory, not a symlink, with no group/world permission bits.
func EnsurePrivateDir(path string) error {
	if path == "" {
		return errors.New("empty directory path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// PathExists reports whether the path exists (without following symlinks).
func PathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// IsUnsafeMode reports whether a mode grants group or world write access.
func IsUnsafeMode(mode os.FileMode) bool {
	return mode.Perm()&0o022 != 0
}

// Canonical returns the cleaned absolute form of path.
func Canonical(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// CanonicalClient canonicalizes a client executable path, resolving symlinks
// and requiring an absolute result. It is used both when enrolling a client and
// when matching observed peer executables.
func CanonicalClient(path string) (string, error) {
	canon, err := Canonical(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(canon); err == nil {
		canon = resolved
	}
	if !filepath.IsAbs(canon) {
		return "", errors.New("client path must be absolute")
	}
	return canon, nil
}

// SHA256File returns the hex-encoded SHA-256 of the file at path.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes returns the hex-encoded SHA-256 of b.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
