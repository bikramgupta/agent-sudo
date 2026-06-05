package broker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSecurePathRejectsSymlinkAndWritableMode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "secure")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	check := securePathCheck{id: "dir", path: dir, kind: securePathDir, uid: os.Getuid()}
	if err := validateSecurePath(check); err != nil {
		t.Fatalf("secure dir rejected: %v", err)
	}
	if err := os.Chmod(dir, 0o722); err != nil {
		t.Fatal(err)
	}
	if err := validateSecurePath(check); err == nil {
		t.Fatal("expected group/world writable dir rejection")
	}

	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	check = securePathCheck{id: "file", path: link, kind: securePathFile, uid: os.Getuid()}
	if err := validateSecurePath(check); err == nil {
		t.Fatal("expected symlink file rejection")
	}
}

func TestValidateSecurePathRejectsWrongOwner(t *testing.T) {
	root := t.TempDir()
	check := securePathCheck{id: "dir", path: root, kind: securePathDir, uid: os.Getuid() + 1}
	if err := validateSecurePath(check); err == nil {
		t.Fatal("expected wrong owner rejection")
	}
}
