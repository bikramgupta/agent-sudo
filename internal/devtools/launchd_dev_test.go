//go:build devtools

package devtools

import (
	"agent-sudo/internal/broker"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/protocol"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLaunchdDevPolicyAllowsOnlyIDAndVerifiedArtifact(t *testing.T) {
	p := launchdDevPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("launchd-dev policy should validate: %v", err)
	}
	req := protocol.BrokerRequest{
		ClientID:   launchdDevClientID,
		CWD:        "/private/tmp",
		Executable: "/usr/bin/id",
		Argv:       []string{"-u"},
	}
	rule, _ := p.Match(req, false, nil)
	if rule == nil || rule.ID != "launchd-dev.id-u" {
		t.Fatalf("expected id policy match, got %#v", rule)
	}
	req.Executable = "/bin/sh"
	req.Argv = []string{"-c", "id"}
	if rule, _ := p.Match(req, false, nil); rule != nil {
		t.Fatalf("shell should not match launchd-dev policy: %#v", rule)
	}
	req.Executable = "id"
	req.Argv = []string{"-u"}
	if rule, _ := p.Match(req, false, nil); rule != nil {
		t.Fatalf("relative executable should not match launchd-dev policy: %#v", rule)
	}
	artReq := protocol.BrokerRequest{
		ClientID:   launchdDevClientID,
		CWD:        "/private/tmp",
		Executable: "/private/tmp/agent-sudo-launchd-dev/artifacts/objects/hash",
		Argv:       []string{},
		ArtifactID: "art_hash",
	}
	if rule, _ := p.Match(artReq, true, nil); rule == nil || rule.ID != "launchd-dev.artifact.verified" {
		t.Fatalf("verified artifact should match, got %#v", rule)
	}
}

func TestLaunchdDevPathSafetyAndMarkerCleanup(t *testing.T) {
	if _, err := cleanLaunchdDevPath("/tmp/not-agent-sudo"); err == nil {
		t.Fatal("expected unsafe launchd-dev path to be rejected")
	}
	if got, err := cleanLaunchdDevPath(defaultLaunchdDevRoot); err != nil || got != defaultLaunchdDevRoot {
		t.Fatalf("default root path got=%q err=%v", got, err)
	}
	root := defaultLaunchdDevRoot + "-test-" + broker.NewRequestID()
	if got, err := cleanLaunchdDevPath(root); err != nil || got != root {
		t.Fatalf("suffixed root path got=%q err=%v", got, err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
	})
	if err := safeRemoveLaunchdDev(root); err == nil {
		t.Fatal("expected cleanup without marker to be rejected")
	}
	if err := os.WriteFile(filepath.Join(root, launchdDevMarker), []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safeRemoveLaunchdDev(root); err != nil {
		t.Fatalf("cleanup with marker failed: %v", err)
	}
	if fsutil.PathExists(root) {
		t.Fatal("launchd-dev directory still exists after cleanup")
	}
}

func TestLaunchdDevPlistGeneration(t *testing.T) {
	plan, err := newLaunchdDevPlan(defaultLaunchdDevRoot, defaultLaunchdDevPlistPath, 20)
	if err != nil {
		t.Fatal(err)
	}
	plist := string(renderLaunchdDevPlist(plan))
	for _, want := range []string{
		"<string>com.bikram.agent-sudo.dev</string>",
		"<string>/private/tmp/agent-sudo-launchd-dev/bin/agent-sudo</string>",
		"<string>broker</string>",
		"<string>serve</string>",
		"<key>AGENT_SUDO_SOCKET</key>",
		"<string>/private/tmp/agent-sudo-launchd-dev/run/broker.sock</string>",
		"<key>HOME</key>",
		"<string>/private/tmp/agent-sudo-launchd-dev</string>",
		"<key>RunAtLoad</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "/etc/", "/usr/local/"} {
		if strings.Contains(plist, forbidden) {
			t.Fatalf("plist contains forbidden path/shell %q:\n%s", forbidden, plist)
		}
	}
}

func TestLaunchdDevEnvironmentIncludesHomeAndExplicitPaths(t *testing.T) {
	plan, err := newLaunchdDevPlan(defaultLaunchdDevRoot, defaultLaunchdDevPlistPath, 20)
	if err != nil {
		t.Fatal(err)
	}
	env := launchdDevEnvironment(plan.Paths)
	want := map[string]string{
		"HOME":                    plan.Paths.Home,
		"AGENT_SUDO_RUN_DIR":      plan.Paths.RunDir,
		"AGENT_SUDO_SOCKET":       plan.Paths.SocketPath,
		"AGENT_SUDO_CONFIG_DIR":   plan.Paths.ConfigDir,
		"AGENT_SUDO_POLICY":       plan.Paths.PolicyPath,
		"AGENT_SUDO_TRUST":        plan.Paths.TrustPath,
		"AGENT_SUDO_STATE_DIR":    plan.Paths.StateDir,
		"AGENT_SUDO_AUDIT":        plan.Paths.AuditPath,
		"AGENT_SUDO_ARTIFACT_DIR": plan.Paths.ArtifactDir,
	}
	for key, value := range want {
		if env[key] != value {
			t.Fatalf("env[%s] = %q want %q", key, env[key], value)
		}
	}
}

func TestLaunchdDevCommandConstruction(t *testing.T) {
	binary := "/private/tmp/agent-sudo-launchd-dev/bin/agent-sudo"
	wantBroker := []string{
		binary,
		"broker",
		"serve",
		"--run-dir-mode", "0750",
		"--socket-mode", "0660",
		"--socket-uid", "0",
		"--socket-gid", "20",
	}
	if got := launchdDevBrokerArgs(binary, 20); !reflect.DeepEqual(got, wantBroker) {
		t.Fatalf("broker args = %#v want %#v", got, wantBroker)
	}
	if got, want := launchdDevBootstrapArgs(defaultLaunchdDevPlistPath), []string{"bootstrap", "system", defaultLaunchdDevPlistPath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrap args = %#v want %#v", got, want)
	}
	if got, want := launchdDevBootoutLabelArgs(launchdDevLabel), []string{"bootout", "system/" + launchdDevLabel}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bootout label args = %#v want %#v", got, want)
	}
	if got, want := launchdDevBootoutPlistArgs(defaultLaunchdDevPlistPath), []string{"bootout", "system", defaultLaunchdDevPlistPath}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bootout plist args = %#v want %#v", got, want)
	}
}

func TestLaunchdDevCheckClientPathPrefersDevBinary(t *testing.T) {
	root := defaultLaunchdDevRoot + "-test-" + broker.NewRequestID()
	plan, err := newLaunchdDevPlan(root, defaultLaunchdDevPlistPath, 20)
	if err != nil {
		t.Fatal(err)
	}
	workspaceBinary := filepath.Join(t.TempDir(), "agent-sudo")
	if got := launchdDevCheckClientPath(plan, workspaceBinary); got != workspaceBinary {
		t.Fatalf("missing dev binary check client = %q want %q", got, workspaceBinary)
	}
	if err := os.MkdirAll(filepath.Dir(plan.BinaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
	})
	if err := os.WriteFile(plan.BinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := launchdDevCheckClientPath(plan, workspaceBinary); got != plan.BinaryPath {
		t.Fatalf("present dev binary check client = %q want %q", got, plan.BinaryPath)
	}
}

func TestLaunchdDevPlanAvoidsRootlessAndProductionPaths(t *testing.T) {
	plan, err := newLaunchdDevPlan(defaultLaunchdDevRoot, defaultLaunchdDevPlistPath, 20)
	if err != nil {
		t.Fatal(err)
	}
	devPaths := []string{
		plan.Root,
		plan.Paths.RunDir,
		plan.Paths.SocketPath,
		plan.Paths.ConfigDir,
		plan.Paths.PolicyPath,
		plan.Paths.TrustPath,
		plan.Paths.StateDir,
		plan.Paths.AuditPath,
		plan.Paths.ArtifactDir,
		plan.BinaryPath,
		plan.StdoutPath,
		plan.StderrPath,
	}
	for _, path := range devPaths {
		if path != defaultLaunchdDevRoot && !strings.HasPrefix(path, defaultLaunchdDevRoot+string(os.PathSeparator)) {
			t.Fatalf("path %q is outside dev root", path)
		}
	}
	joined := strings.Join(devPaths, "\n") + "\n" + string(renderLaunchdDevPlist(plan))
	for _, forbidden := range []string{
		"/etc/",
		"/usr/local/",
		"/.config/agent-sudo",
		"/.local/state/agent-sudo",
		"/.agent-sudo/run",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("launchd-dev plan contains forbidden production/rootless path %q:\n%s", forbidden, joined)
		}
	}
}
