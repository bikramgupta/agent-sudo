//go:build devtools

package devtools

import (
	"agent-sudo/internal/broker"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/protocol"
	"os"
	"path/filepath"
	"testing"
)

func TestRootSmokePolicyAllowsOnlyIDAndVerifiedArtifact(t *testing.T) {
	p := rootSmokePolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("root smoke policy should validate: %v", err)
	}
	req := protocol.BrokerRequest{
		ClientID:   rootSmokeClientID,
		CWD:        "/private/tmp",
		Executable: "/usr/bin/id",
		Argv:       []string{"-u"},
	}
	rule, _ := p.Match(req, false, nil)
	if rule == nil || rule.ID != "root-smoke.id-u" {
		t.Fatalf("expected id policy match, got %#v", rule)
	}
	req.Executable = "/bin/sh"
	req.Argv = []string{"-c", "id"}
	if rule, _ := p.Match(req, false, nil); rule != nil {
		t.Fatalf("shell should not match root smoke policy: %#v", rule)
	}
	req.Executable = "id"
	req.Argv = []string{"-u"}
	if rule, _ := p.Match(req, false, nil); rule != nil {
		t.Fatalf("relative executable should not match root smoke policy: %#v", rule)
	}
	artReq := protocol.BrokerRequest{
		ClientID:   rootSmokeClientID,
		CWD:        "/private/tmp",
		Executable: "/private/tmp/agent-sudo-root-smoke/artifacts/objects/hash",
		Argv:       []string{},
		ArtifactID: "art_hash",
	}
	if rule, _ := p.Match(artReq, true, nil); rule == nil || rule.ID != "root-smoke.artifact.verified" {
		t.Fatalf("verified artifact should match, got %#v", rule)
	}
	if rule, _ := p.Match(artReq, false, nil); rule != nil {
		t.Fatalf("unverified artifact should not match: %#v", rule)
	}
}

func TestRootSmokePathSafety(t *testing.T) {
	if _, err := cleanRootSmokePath("/tmp/not-agent-sudo"); err == nil {
		t.Fatal("expected unsafe root-smoke path to be rejected")
	}
	if got, err := cleanRootSmokePath(defaultRootSmokeDir); err != nil || got != defaultRootSmokeDir {
		t.Fatalf("default root path got=%q err=%v", got, err)
	}
	if got, err := cleanRootSmokePath(defaultRootSmokeDir + "-dev"); err != nil || got != defaultRootSmokeDir+"-dev" {
		t.Fatalf("suffixed root path got=%q err=%v", got, err)
	}
}

func TestRootSmokeLaunchdDevControlCommandMapping(t *testing.T) {
	for _, subcommand := range []string{
		"launchd-dev-status",
		"launchd-dev-diagnose",
		"launchd-dev-install",
		"launchd-dev-check",
		"launchd-dev-uninstall",
		"launchd-dev-cycle",
	} {
		got, err := rootSmokeLaunchdDevControlCommand(subcommand)
		if err != nil {
			t.Fatalf("%s returned error: %v", subcommand, err)
		}
		if got != subcommand {
			t.Fatalf("%s mapped to %q", subcommand, got)
		}
	}
	if _, err := rootSmokeLaunchdDevControlCommand("launchd-dev-shell"); err == nil {
		t.Fatal("expected unknown launchd-dev control command to be rejected")
	}
}

func TestSafeRemoveRequiresMarker(t *testing.T) {
	root := filepath.Join("/private/tmp", "agent-sudo-root-smoke-test-"+broker.NewRequestID())
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
	})
	if err := safeRemoveRootSmoke(root); err == nil {
		t.Fatal("expected cleanup without marker to be rejected")
	}
	if err := os.WriteFile(filepath.Join(root, rootSmokeMarker), []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safeRemoveRootSmoke(root); err != nil {
		t.Fatalf("cleanup with marker failed: %v", err)
	}
	if fsutil.PathExists(root) {
		t.Fatal("root smoke directory still exists after cleanup")
	}
}

func TestVerifyPathDetectsWrongMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	check := verifyPath("tmp", dir, os.Getuid(), -1, 0o700, true)
	if check.Status != "PASS" {
		t.Fatalf("expected temp dir to pass, got %#v", check)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	check = verifyPath("tmp", dir, os.Getuid(), -1, 0o700, true)
	if check.Status != "FAIL" {
		t.Fatalf("expected mode failure, got %#v", check)
	}
}
