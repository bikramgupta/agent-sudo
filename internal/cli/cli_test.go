package cli

import (
	"agent-sudo/internal/artifact"
	"agent-sudo/internal/audit"
	"agent-sudo/internal/broker"
	"agent-sudo/internal/config"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/peer"
	"agent-sudo/internal/policy"
	"agent-sudo/internal/protocol"
	"agent-sudo/internal/selftest"
	"agent-sudo/internal/trust"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildCommandRequestRequiresSeparatorAndPreservesArgv(t *testing.T) {
	req, _, err := buildCommandRequest([]string{
		"--reason", "Run echo command for broker project target test.",
		"--client", "test-client",
		"--",
		"/bin/echo", "hello",
	}, "", "")
	if err != nil {
		t.Fatalf("buildCommandRequest: %v", err)
	}
	if req.Executable != "/bin/echo" {
		t.Fatalf("executable = %q", req.Executable)
	}
	if got := strings.Join(req.Argv, ","); got != "hello" {
		t.Fatalf("argv = %q", got)
	}
	if req.ClientID != "test-client" {
		t.Fatalf("client = %q", req.ClientID)
	}
	if _, _, err := buildCommandRequest([]string{
		"--reason", "Run echo command for broker project target test.",
		"/bin/echo", "hello",
	}, "", ""); err == nil {
		t.Fatal("expected missing separator error")
	}
}

func TestTrustAddParserMatchesDocumentedOrder(t *testing.T) {
	id, path, err := parseTrustAddArgs([]string{"codex", "--path", "/tmp/agent-sudo"})
	if err != nil {
		t.Fatalf("parseTrustAddArgs: %v", err)
	}
	if id != "codex" || path != "/tmp/agent-sudo" {
		t.Fatalf("id=%q path=%q", id, path)
	}
}

func TestReasonValidation(t *testing.T) {
	if resp := policy.ValidateReason("sudo", protocol.EffectReadOnly, "/bin/echo", []string{"hello"}); resp == nil || resp.Decision != protocol.DecisionReasonInvalid || !resp.Retryable {
		t.Fatalf("weak reason response = %#v", resp)
	}
	if resp := policy.ValidateReason("Validate policy target file for broker project test.", protocol.EffectValidateOnly, "/usr/sbin/visudo", []string{"-c"}); resp != nil {
		t.Fatalf("valid reason rejected: %#v", resp)
	}
	if resp := policy.ValidateReason("Validate broker target policy before continuing.", protocol.EffectInstallOrUpdate, "/opt/homebrew/bin/brew", []string{"install", "jq"}); resp == nil || resp.Decision != protocol.DecisionReasonInvalid {
		t.Fatalf("expected mismatch reason invalid, got %#v", resp)
	}
}

func TestPolicyDefaultDenyAndExactMatch(t *testing.T) {
	p := policy.Policy{Version: 1, Rules: []policy.PolicyRule{
		{
			ID:         "sudoers.validate",
			Clients:    []string{"test-client"},
			Executable: "/usr/sbin/visudo",
			Argv: []policy.ArgMatcher{
				exact("-c"),
				exact("-f"),
				prefix("/etc/sudoers.d/"),
			},
			Effect:   protocol.EffectValidateOnly,
			Approval: "not_required",
		},
	}}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy validate: %v", err)
	}
	req := protocol.BrokerRequest{ClientID: "test-client", CWD: t.TempDir(), Executable: "/usr/sbin/visudo", Argv: []string{"-c", "-f", "/etc/sudoers.d/lima"}}
	rule, _ := p.Match(req, false, nil)
	if rule == nil || rule.ID != "sudoers.validate" {
		t.Fatalf("expected exact policy match, got %#v", rule)
	}
	req.Argv = []string{"-f", "/etc/sudoers.d/lima"}
	if rule, _ := p.Match(req, false, nil); rule != nil {
		t.Fatalf("expected policy mismatch for mutation-capable visudo args")
	}
	req.Executable = "/bin/unknown"
	if rule, _ := p.Match(req, false, nil); rule != nil {
		t.Fatalf("expected default deny for unknown executable")
	}
}

func TestPolicyRejectsBroadShellRule(t *testing.T) {
	p := policy.Policy{Version: 1, Rules: []policy.PolicyRule{{
		ID:         "shell.raw",
		Clients:    []string{"test-client"},
		Executable: "/bin/sh",
		Argv:       []policy.ArgMatcher{exact("-c"), exact("id")},
		Effect:     protocol.EffectDestructive,
		Approval:   "not_required",
	}}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected shell rule without allow_shell to be rejected")
	}
}

func TestBrokerSecurityNegatives(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.Policy{Version: 1, Rules: []policy.PolicyRule{{
		ID:         "echo.hello",
		Clients:    []string{"test-client"},
		Executable: "/bin/echo",
		Argv:       []policy.ArgMatcher{exact("hello")},
		Effect:     protocol.EffectReadOnly,
		Approval:   "not_required",
	}}})
	trustTestBinary(t, paths, "test-client")
	b := mustBroker(t, paths)

	req := trustedRequest(t, "test-client", t.TempDir(), "/bin/echo", []string{"hello"})
	req.Reason = "Run echo command for broker project target test."
	req.Env = map[string]string{"DYLD_INSERT_LIBRARIES": "[present]"}
	resp := b.Process(req)
	if resp.Decision != protocol.DecisionDenied {
		t.Fatalf("env injection decision = %#v", resp)
	}

	req = trustedRequest(t, "test-client", t.TempDir(), "/bin/echo", []string{"hello|id"})
	req.Reason = "Run echo command for broker project target test."
	resp = b.Process(req)
	if resp.Decision == protocol.DecisionApproved {
		t.Fatalf("shell metacharacter unexpectedly approved: %#v", resp)
	}

	req = trustedRequest(t, "test-client", t.TempDir(), "brew", []string{"install", "jq"})
	req.Reason = "Install jq package for broker project target scripts."
	resp = b.Process(req)
	if resp.Decision == protocol.DecisionApproved {
		t.Fatalf("relative executable unexpectedly approved: %#v", resp)
	}
}

func TestBrokerRejectsClientMetadataMismatchWithObservedPeer(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.DefaultPolicy())
	trustTestBinary(t, paths, "test-client")
	b := mustBroker(t, paths)

	req := trustedRequest(t, "test-client", t.TempDir(), "/bin/echo", []string{"hello"})
	req.Reason = "Run echo command for broker project target test."
	peer := peerForRequest(t, req)
	req.ClientExecutable = "/bin/sh"
	req.ClientSHA256 = strings.Repeat("0", 64)

	resp := b.ProcessWithPeer(req, &peer)
	if resp.Decision != protocol.DecisionClientNotTrusted {
		t.Fatalf("expected client metadata mismatch denial, got %#v", resp)
	}
	event := readFirstAuditEvent(t, paths.AuditPath, req.RequestID)
	if event.Decision != protocol.DecisionClientNotTrusted || event.PeerPID != peer.PID || event.UID != peer.UID {
		t.Fatalf("audit event = %#v peer=%#v", event, peer)
	}
}

func TestRootlessBrokerRoundTripAndAudit(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.DefaultPolicy())
	trustTestBinary(t, paths, "test-client")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startBroker(t, ctx, paths)

	req := trustedRequest(t, "test-client", t.TempDir(), "/bin/echo", []string{"hello"})
	req.Reason = "Run echo command for broker project target test."
	resp, err := broker.Send(context.Background(), paths.SocketPath, req)
	if err != nil {
		t.Fatalf("broker.Send: %v", err)
	}
	if resp.Decision != protocol.DecisionApproved || resp.ExitCode != 0 || resp.Stdout != "hello\n" {
		t.Fatalf("response = %#v", resp)
	}
	event := readFirstAuditEvent(t, paths.AuditPath, req.RequestID)
	if event.Decision != protocol.DecisionApproved || event.PolicyID != "dev.echo.hello" || event.StdoutSHA256 == "" {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestSocketBrokerDerivesPeerIdentityAndRejectsSpoof(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.DefaultPolicy())
	trustTestBinary(t, paths, "test-client")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startBroker(t, ctx, paths)

	req := protocol.BrokerRequest{
		SchemaVersion:    1,
		Type:             "command",
		RequestID:        broker.NewRequestID(),
		ClientID:         "test-client",
		ClientExecutable: "/bin/sh",
		ClientSHA256:     strings.Repeat("0", 64),
		CWD:              t.TempDir(),
		Reason:           "Run echo command for broker project target test.",
		Executable:       "/bin/echo",
		Argv:             []string{"hello"},
		Env:              map[string]string{},
	}
	resp, err := broker.Send(context.Background(), paths.SocketPath, req)
	if err != nil {
		t.Fatalf("send spoof request: %v", err)
	}
	if resp.Decision != protocol.DecisionClientNotTrusted {
		t.Fatalf("expected spoofed metadata denial, got %#v", resp)
	}

	req.RequestID = broker.NewRequestID()
	req.ClientExecutable = ""
	req.ClientSHA256 = ""
	resp, err = broker.Send(context.Background(), paths.SocketPath, req)
	if err != nil {
		t.Fatalf("send derived request: %v", err)
	}
	if resp.Decision != protocol.DecisionApproved || resp.Stdout != "hello\n" {
		t.Fatalf("expected broker-derived identity approval, got %#v", resp)
	}
}

func TestBrokerUnavailableDoesNotFallback(t *testing.T) {
	resp, err := broker.Send(context.Background(), filepath.Join(t.TempDir(), "missing.sock"), protocol.BrokerRequest{RequestID: "req_test"})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if resp.Decision != "BROKER_UNAVAILABLE" || !resp.Retryable {
		t.Fatalf("response = %#v", resp)
	}
}

func TestReasonInvalidIsRetryableAndAudited(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.DefaultPolicy())
	trustTestBinary(t, paths, "test-client")
	b := mustBroker(t, paths)
	req := trustedRequest(t, "test-client", t.TempDir(), "/bin/echo", []string{"hello"})
	req.Reason = "sudo"
	resp := b.Process(req)
	if resp.Decision != protocol.DecisionReasonInvalid || !resp.Retryable || len(resp.Missing) == 0 {
		t.Fatalf("response = %#v", resp)
	}
	event := readFirstAuditEvent(t, paths.AuditPath, req.RequestID)
	if event.Decision != protocol.DecisionReasonInvalid || !event.Retryable {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestArtifactImportRejectsSymlinkWritableParentAndHashTamper(t *testing.T) {
	paths := setupRootlessPaths(t)
	store := artifact.NewStore(paths.ArtifactDir)
	safeDir := t.TempDir()
	source := filepath.Join(safeDir, "script.sh")
	if err := os.WriteFile(source, []byte("#!/bin/sh\necho original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(safeDir, "link.sh")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(link); err == nil {
		t.Fatal("expected symlink import to fail")
	}

	badDir := filepath.Join(t.TempDir(), "world")
	if err := os.Mkdir(badDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(badDir, 0o777); err != nil {
		t.Fatal(err)
	}
	badSource := filepath.Join(badDir, "script.sh")
	if err := os.WriteFile(badSource, []byte("#!/bin/sh\necho bad\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(badSource); err == nil {
		t.Fatal("expected writable-parent import to fail")
	}

	meta, err := store.Import(source)
	if err != nil {
		t.Fatalf("import safe source: %v", err)
	}
	object := store.ObjectPath(meta.SHA256)
	if err := os.Chmod(object, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("#!/bin/sh\necho tampered\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Verify(meta.ID); err == nil {
		t.Fatal("expected tampered stored artifact to fail verification")
	}
}

func TestArtifactRunUsesStoredContentAfterSourceMutation(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.DefaultPolicy())
	trustTestBinary(t, paths, "test-client")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startBroker(t, ctx, paths)

	store := artifact.NewStore(paths.ArtifactDir)
	safeDir := t.TempDir()
	source := filepath.Join(safeDir, "script.sh")
	if err := os.WriteFile(source, []byte("#!/bin/sh\necho original\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := store.Import(source)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if err := os.WriteFile(source, []byte("#!/bin/sh\necho changed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	verified, object, err := store.Verify(meta.ID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	req := trustedRequest(t, "test-client", t.TempDir(), object, nil)
	req.Reason = "Run verified artifact script for broker project target test."
	req.ArtifactID = verified.ID
	req.ArtifactSHA256 = verified.SHA256
	resp, err := broker.Send(context.Background(), paths.SocketPath, req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Decision != protocol.DecisionApproved || resp.Stdout != "original\n" {
		t.Fatalf("artifact run response = %#v", resp)
	}
}

func TestFetchRequiresHTTPSAndPinnedChecksum(t *testing.T) {
	paths := setupRootlessPaths(t)
	store := artifact.NewStore(paths.ArtifactDir)
	body := []byte("#!/bin/sh\necho fetched\n")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       ioNopCloser{strings.NewReader(string(body))},
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	if _, err := store.Fetch(context.Background(), "http://example.invalid/install.sh", hash, client, 1<<20); err == nil {
		t.Fatal("expected HTTP fetch to be denied")
	}

	meta, err := store.Fetch(context.Background(), "https://example.invalid/install.sh", hash, client, 1<<20)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if meta.SHA256 != hash || meta.SourceType != "fetch" {
		t.Fatalf("metadata = %#v", meta)
	}
	if _, err := store.Fetch(context.Background(), "https://example.invalid/install.sh", strings.Repeat("0", 64), client, 1<<20); err == nil {
		t.Fatal("expected wrong checksum to fail")
	}
}

func TestSelfTestRootlessPaths(t *testing.T) {
	paths := setupRootlessPaths(t)
	for _, dir := range []string{paths.RunDir, paths.ConfigDir, paths.StateDir, paths.ArtifactDir} {
		if err := fsutil.EnsurePrivateDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := policy.SaveDefaultPolicy(paths.PolicyPath); err != nil {
		t.Fatal(err)
	}
	trustTestBinary(t, paths, "test-client")
	result := selftest.Run(paths)
	if result.Status == "FAIL" {
		t.Fatalf("self-test failed: %#v", result)
	}
}

func TestDefaultPathsAllowExplicitEnvWithoutHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("AGENT_SUDO_RUN_DIR", filepath.Join(root, "run"))
	t.Setenv("AGENT_SUDO_SOCKET", filepath.Join(root, "run", "broker.sock"))
	t.Setenv("AGENT_SUDO_CONFIG_DIR", filepath.Join(root, "config"))
	t.Setenv("AGENT_SUDO_POLICY", filepath.Join(root, "config", "policy.yaml"))
	t.Setenv("AGENT_SUDO_TRUST", filepath.Join(root, "config", "trust.json"))
	t.Setenv("AGENT_SUDO_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("AGENT_SUDO_AUDIT", filepath.Join(root, "audit", "audit.jsonl"))
	t.Setenv("AGENT_SUDO_ARTIFACT_DIR", filepath.Join(root, "artifacts"))

	paths, err := config.DefaultPaths()
	if err != nil {
		t.Fatalf("config.DefaultPaths should allow explicit launchd-style env without HOME: %v", err)
	}
	if paths.SocketPath != filepath.Join(root, "run", "broker.sock") || paths.PolicyPath != filepath.Join(root, "config", "policy.yaml") {
		t.Fatalf("paths did not use explicit env: %#v", paths)
	}
}

func TestRedactionAndBoundedCapture(t *testing.T) {
	c := audit.NewCapture(8)
	_, _ = c.Write([]byte("token=abcdef0123456789\nmore-output"))
	if !c.Truncated() {
		t.Fatal("expected capture truncation")
	}
	if tail := c.Tail(64); strings.Contains(tail, "abcdef") {
		t.Fatalf("secret tail was not redacted: %q", tail)
	}
	if c.SHA256() == "" {
		t.Fatal("missing sha256")
	}
}

func TestAuditCapturesFullOutputHashAndTruncation(t *testing.T) {
	paths := setupRootlessPaths(t)
	arg := strings.Repeat("A", 100)
	writePolicy(t, paths, policy.Policy{Version: 1, Rules: []policy.PolicyRule{{
		ID:               "echo.big",
		Clients:          []string{"test-client"},
		Executable:       "/bin/echo",
		Argv:             []policy.ArgMatcher{exact(arg)},
		Effect:           protocol.EffectReadOnly,
		Approval:         "not_required",
		TimeoutSeconds:   10,
		OutputLimitBytes: 8,
	}}})
	trustTestBinary(t, paths, "test-client")
	b := mustBroker(t, paths)

	req := trustedRequest(t, "test-client", t.TempDir(), "/bin/echo", []string{arg})
	req.Reason = "Run echo command for broker project target test."
	resp := b.Process(req)
	if resp.Decision != protocol.DecisionApproved {
		t.Fatalf("response = %#v", resp)
	}
	if len(resp.Stdout) != 8 {
		t.Fatalf("expected bounded stdout of 8 bytes, got %d (%q)", len(resp.Stdout), resp.Stdout)
	}
	// The audit record must describe the full pre-truncation output, not the
	// bounded copy returned to the client.
	fullSum := sha256.Sum256([]byte(arg + "\n"))
	wantHash := hex.EncodeToString(fullSum[:])
	event := readFirstAuditEvent(t, paths.AuditPath, req.RequestID)
	if event.StdoutLen != int64(len(arg)+1) {
		t.Fatalf("audit StdoutLen = %d, want %d", event.StdoutLen, len(arg)+1)
	}
	if !event.StdoutTruncated {
		t.Fatal("audit StdoutTruncated = false, want true")
	}
	if event.StdoutSHA256 != wantHash {
		t.Fatalf("audit StdoutSHA256 = %s, want full-output hash %s", event.StdoutSHA256, wantHash)
	}
}

func TestExecuteTimeoutIsAuditedAndTerminated(t *testing.T) {
	paths := setupRootlessPaths(t)
	writePolicy(t, paths, policy.Policy{Version: 1, Rules: []policy.PolicyRule{{
		ID:             "sleep.timeout",
		Clients:        []string{"test-client"},
		Executable:     "/bin/sleep",
		Argv:           []policy.ArgMatcher{exact("5")},
		Effect:         protocol.EffectReadOnly,
		Approval:       "not_required",
		TimeoutSeconds: 1,
	}}})
	trustTestBinary(t, paths, "test-client")
	b := mustBroker(t, paths)

	req := trustedRequest(t, "test-client", t.TempDir(), "/bin/sleep", []string{"5"})
	req.Reason = "Run sleep command for broker project timeout test."
	start := time.Now()
	resp := b.Process(req)
	elapsed := time.Since(start)
	if resp.Decision != protocol.DecisionApproved || resp.ExitCode != 124 {
		t.Fatalf("expected timeout exit 124, got %#v", resp)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("timeout did not terminate promptly: %v", elapsed)
	}
	event := readFirstAuditEvent(t, paths.AuditPath, req.RequestID)
	if !event.Timeout {
		t.Fatalf("audit Timeout = false, want true: %#v", event)
	}
}

func setupRootlessPaths(t *testing.T) config.Paths {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "agent-sudo-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(root)
	})
	return config.Paths{
		Home:        root,
		RunDir:      filepath.Join(root, ".agent-sudo", "run"),
		SocketPath:  filepath.Join(root, ".agent-sudo", "run", "broker.sock"),
		ConfigDir:   filepath.Join(root, ".config", "agent-sudo"),
		PolicyPath:  filepath.Join(root, ".config", "agent-sudo", "policy.yaml"),
		TrustPath:   filepath.Join(root, ".config", "agent-sudo", "trust.json"),
		StateDir:    filepath.Join(root, ".local", "state", "agent-sudo"),
		AuditPath:   filepath.Join(root, ".local", "state", "agent-sudo", "audit.jsonl"),
		ArtifactDir: filepath.Join(root, ".local", "state", "agent-sudo", "artifacts"),
	}
}

func writePolicy(t *testing.T, paths config.Paths, policy policy.Policy) {
	t.Helper()
	if err := fsutil.EnsurePrivateDir(filepath.Dir(paths.PolicyPath)); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.PolicyPath, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func trustTestBinary(t *testing.T, paths config.Paths, id string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.AddClient(paths.TrustPath, id, exe); err != nil {
		t.Fatal(err)
	}
}

func mustBroker(t *testing.T, paths config.Paths) *broker.Broker {
	t.Helper()
	b, err := broker.New(paths)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func startBroker(t *testing.T, ctx context.Context, paths config.Paths) {
	t.Helper()
	b := mustBroker(t, paths)
	errCh := make(chan error, 1)
	go func() {
		errCh <- b.Serve(ctx)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fsutil.PathExists(paths.SocketPath) {
			return
		}
		select {
		case err := <-errCh:
			t.Fatalf("broker exited: %v", err)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("broker socket did not appear")
}

func trustedRequest(t *testing.T, clientID, cwd, executable string, argv []string) protocol.BrokerRequest {
	t.Helper()
	req := protocol.BrokerRequest{
		SchemaVersion: 1,
		Type:          "command",
		RequestID:     broker.NewRequestID(),
		ClientID:      clientID,
		CWD:           cwd,
		Executable:    executable,
		Argv:          argv,
		Env:           map[string]string{},
	}
	if err := broker.FillClientMetadata(&req); err != nil {
		t.Fatal(err)
	}
	return req
}

func peerForRequest(t *testing.T, req protocol.BrokerRequest) peer.Identity {
	t.Helper()
	return peer.Identity{
		UID:        os.Getuid(),
		GID:        os.Getgid(),
		PID:        os.Getpid(),
		Executable: req.ClientExecutable,
		SHA256:     req.ClientSHA256,
	}
}

func readFirstAuditEvent(t *testing.T, path, requestID string) audit.Event {
	t.Helper()
	event, err := audit.Show(path, requestID)
	if err != nil {
		t.Fatal(err)
	}
	return *event
}

func exact(s string) policy.ArgMatcher {
	return policy.ArgMatcher{Exact: &s}
}

func prefix(s string) policy.ArgMatcher {
	return policy.ArgMatcher{Prefix: &s}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type ioNopCloser struct {
	*strings.Reader
}

func (c ioNopCloser) Close() error {
	return nil
}
