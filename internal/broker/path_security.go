package broker

import (
	"agent-sudo/internal/config"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validatePrivilegedBrokerPaths(paths config.Paths) error {
	checks := []securePathCheck{
		{id: "run_dir", path: paths.RunDir, kind: securePathDir, uid: 0, allowMissing: false},
		{id: "config_dir", path: paths.ConfigDir, kind: securePathDir, uid: 0, allowMissing: false},
		{id: "policy_file", path: paths.PolicyPath, kind: securePathFile, uid: 0, allowMissing: false},
		{id: "trust_file", path: paths.TrustPath, kind: securePathFile, uid: 0, allowMissing: false},
		{id: "audit_dir", path: filepath.Dir(paths.AuditPath), kind: securePathDir, uid: 0, allowMissing: false},
		{id: "artifact_dir", path: paths.ArtifactDir, kind: securePathDir, uid: 0, allowMissing: false},
	}
	for _, check := range checks {
		if err := validateSecurePath(check); err != nil {
			return err
		}
	}
	return nil
}

type securePathKind string

const (
	securePathDir  securePathKind = "directory"
	securePathFile securePathKind = "file"
)

type securePathCheck struct {
	id           string
	path         string
	kind         securePathKind
	uid          int
	allowMissing bool
}

func validateSecurePath(check securePathCheck) error {
	info, err := os.Lstat(check.path)
	if err != nil {
		if check.allowMissing && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%s %s: %w", check.id, check.path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s is a symlink", check.id, check.path)
	}
	switch check.kind {
	case securePathDir:
		if !info.IsDir() {
			return fmt.Errorf("%s %s is not a directory", check.id, check.path)
		}
	case securePathFile:
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s %s is not a regular file", check.id, check.path)
		}
	default:
		return fmt.Errorf("%s %s has unknown secure path kind", check.id, check.path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s is group/world writable", check.id, check.path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s %s ownership unavailable", check.id, check.path)
	}
	if int(st.Uid) != check.uid {
		return fmt.Errorf("%s %s uid=%d want=%d", check.id, check.path, st.Uid, check.uid)
	}
	return nil
}
