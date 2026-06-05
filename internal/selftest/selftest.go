package selftest

import (
	"agent-sudo/internal/broker"
	"agent-sudo/internal/config"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/policy"
	"agent-sudo/internal/protocol"
	"agent-sudo/internal/trust"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Result struct {
	Status string  `json:"status"`
	Checks []Check `json:"checks"`
}

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func Run(paths config.Paths) Result {
	checks := []Check{}
	add := func(id, status, msg string) {
		checks = append(checks, Check{ID: id, Status: status, Message: msg})
	}
	checkPathDir := func(id, path string) {
		info, err := os.Lstat(path)
		if err != nil {
			add(id, "FAIL", err.Error())
			return
		}
		if info.Mode()&os.ModeSymlink != 0 {
			add(id, "FAIL", path+" is a symlink")
			return
		}
		if !info.IsDir() {
			add(id, "FAIL", path+" is not a directory")
			return
		}
		if fsutil.IsUnsafeMode(info.Mode()) {
			add(id, "FAIL", path+" is group/world writable")
			return
		}
		add(id, "PASS", path)
	}
	checkPathDir("run_dir", paths.RunDir)
	checkPathDir("config_dir", paths.ConfigDir)
	checkPathDir("state_dir", paths.StateDir)
	checkPathDir("artifact_dir", paths.ArtifactDir)

	if pol, err := policy.LoadPolicy(paths.PolicyPath); err != nil {
		add("policy_load", "FAIL", err.Error())
	} else if len(pol.Rules) == 0 {
		add("policy_load", "WARN", "policy has no rules; requests will default deny")
	} else {
		add("policy_load", "PASS", paths.PolicyPath)
	}
	if trustStore, err := trust.Load(paths.TrustPath); err != nil {
		add("trust_load", "FAIL", err.Error())
	} else if len(trustStore.Clients) == 0 {
		add("trust_load", "WARN", "no trusted clients enrolled")
	} else {
		add("trust_load", "PASS", paths.TrustPath)
	}
	if fsutil.PathExists(paths.SocketPath) {
		if info, err := os.Lstat(paths.SocketPath); err != nil {
			add("socket", "FAIL", err.Error())
		} else if info.Mode().Perm()&0o077 != 0 {
			add("socket", "FAIL", "socket is group/world accessible")
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			req := protocol.BrokerRequest{SchemaVersion: 1, Type: "ping", RequestID: broker.NewRequestID()}
			resp, err := broker.Send(ctx, paths.SocketPath, req)
			cancel()
			if err != nil {
				add("socket", "WARN", "socket exists but broker did not respond")
			} else {
				add("socket", "PASS", resp.Message)
			}
		}
	} else {
		add("socket", "WARN", "broker socket is not present")
	}
	if err := checkAuditParent(paths.AuditPath); err != nil {
		add("audit_path", "FAIL", err.Error())
	} else {
		add("audit_path", "PASS", filepath.Dir(paths.AuditPath))
	}
	if sudoBypassAvailable() {
		add("sudo_bypass", "WARN", "sudo -n succeeded; direct sudo bypass may exist outside the broker")
	} else {
		add("sudo_bypass", "PASS", "no non-interactive sudo bypass detected")
	}

	status := "PASS"
	for _, c := range checks {
		if c.Status == "FAIL" {
			status = "FAIL"
			break
		}
		if c.Status == "WARN" && status == "PASS" {
			status = "WARN"
		}
	}
	return Result{Status: status, Checks: checks}
}

func checkAuditParent(path string) error {
	return fsutil.EnsurePrivateDir(filepath.Dir(path))
}

func sudoBypassAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "-v")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
