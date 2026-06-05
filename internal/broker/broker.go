package broker

import (
	"agent-sudo/internal/artifact"
	"agent-sudo/internal/audit"
	"agent-sudo/internal/config"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/peer"
	"agent-sudo/internal/policy"
	"agent-sudo/internal/protocol"
	"agent-sudo/internal/trust"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Broker struct {
	paths     config.Paths
	policy    policy.Policy
	trust     trust.Store
	audit     *audit.Logger
	artifacts artifact.Store
}

type ServeOptions struct {
	RunDirMode os.FileMode
	SocketMode os.FileMode
	SocketUID  int
	SocketGID  int
}

func New(paths config.Paths) (*Broker, error) {
	if os.Geteuid() == 0 {
		if err := validatePrivilegedBrokerPaths(paths); err != nil {
			return nil, err
		}
	}
	pol, err := policy.LoadPolicy(paths.PolicyPath)
	if err != nil {
		return nil, err
	}
	trustStore, err := trust.Load(paths.TrustPath)
	if err != nil {
		return nil, err
	}
	return &Broker{
		paths:     paths,
		policy:    pol,
		trust:     trustStore,
		audit:     audit.NewLogger(paths.AuditPath),
		artifacts: artifact.NewStore(paths.ArtifactDir),
	}, nil
}

func (b *Broker) Serve(ctx context.Context) error {
	return b.ServeWithOptions(ctx, ServeOptions{
		RunDirMode: 0o700,
		SocketMode: 0o600,
		SocketUID:  -1,
		SocketGID:  -1,
	})
}

func (b *Broker) ServeWithOptions(ctx context.Context, opts ServeOptions) error {
	if opts.RunDirMode == 0 {
		opts.RunDirMode = 0o700
	}
	if opts.SocketMode == 0 {
		opts.SocketMode = 0o600
	}
	if err := fsutil.EnsurePrivateDir(b.paths.RunDir); err != nil {
		return err
	}
	if opts.RunDirMode != 0o700 {
		if err := os.Chmod(b.paths.RunDir, opts.RunDirMode); err != nil {
			return err
		}
		if opts.SocketGID >= 0 && os.Geteuid() == 0 {
			if err := os.Chown(b.paths.RunDir, 0, opts.SocketGID); err != nil {
				return err
			}
		}
	}
	if err := fsutil.EnsurePrivateDir(filepath.Dir(b.paths.SocketPath)); err != nil {
		return err
	}
	if opts.RunDirMode != 0o700 {
		if err := os.Chmod(filepath.Dir(b.paths.SocketPath), opts.RunDirMode); err != nil {
			return err
		}
		if opts.SocketGID >= 0 && os.Geteuid() == 0 {
			if err := os.Chown(filepath.Dir(b.paths.SocketPath), 0, opts.SocketGID); err != nil {
				return err
			}
		}
	}
	if fsutil.PathExists(b.paths.SocketPath) {
		if err := os.Remove(b.paths.SocketPath); err != nil {
			return err
		}
	}
	l, err := net.Listen("unix", b.paths.SocketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	if opts.SocketUID >= 0 || opts.SocketGID >= 0 {
		uid := opts.SocketUID
		gid := opts.SocketGID
		if uid < 0 {
			uid = 0
		}
		if gid < 0 {
			gid = 0
		}
		if err := os.Chown(b.paths.SocketPath, uid, gid); err != nil {
			return err
		}
	}
	if err := os.Chmod(b.paths.SocketPath, opts.SocketMode); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				errCh <- err
				return <-errCh
			}
		}
		go b.handleConn(conn)
	}
}

func (b *Broker) handleConn(conn net.Conn) {
	defer conn.Close()
	peer, peerErr := peer.Observe(conn)
	var req protocol.BrokerRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(protocol.Denial("", protocol.DecisionDenied, "Invalid request JSON.", false))
		return
	}
	if peerErr != nil {
		resp := protocol.Denial(req.RequestID, protocol.DecisionClientNotTrusted, "Could not observe Unix socket peer identity: "+peerErr.Error(), false)
		_ = json.NewEncoder(conn).Encode(resp)
		return
	}
	resp := b.ProcessWithPeer(req, &peer)
	_ = json.NewEncoder(conn).Encode(resp)
}

func (b *Broker) Process(req protocol.BrokerRequest) protocol.BrokerResponse {
	return b.ProcessWithPeer(req, nil)
}

func (b *Broker) ProcessWithPeer(req protocol.BrokerRequest, pident *peer.Identity) protocol.BrokerResponse {
	start := time.Now()
	if req.RequestID == "" {
		req.RequestID = NewRequestID()
	}
	if pident != nil {
		if mismatch := peer.ApplyObserved(&req, *pident); mismatch != nil {
			resp := *mismatch
			event := auditEventFrom(req, resp, start)
			_ = b.audit.Append(event)
			return resp
		}
	}
	resp := b.process(req, start)
	event := auditEventFrom(req, resp, start)
	if err := b.audit.Append(event); err != nil && resp.Decision == protocol.DecisionApproved {
		return *protocol.Denial(req.RequestID, protocol.DecisionDenied, "Audit log write failed; refusing to claim success.", false)
	}
	return resp
}

func (b *Broker) process(req protocol.BrokerRequest, start time.Time) protocol.BrokerResponse {
	if req.Type == "ping" {
		return protocol.BrokerResponse{RequestID: req.RequestID, Decision: protocol.DecisionApproved, Message: "broker is running"}
	}
	if req.SchemaVersion != 1 {
		return *protocol.Denial(req.RequestID, protocol.DecisionDenied, "Unsupported request schema version.", false)
	}
	if !b.trust.Match(req) {
		return *protocol.Denial(req.RequestID, protocol.DecisionClientNotTrusted, b.trust.MismatchMessage(req), false)
	}
	if req.CWD == "" {
		return *protocol.Denial(req.RequestID, protocol.DecisionDenied, "Request cwd is required.", false)
	}
	if req.ArtifactID == "" {
		if !filepath.IsAbs(req.Executable) {
			return *protocol.Denial(req.RequestID, protocol.DecisionPolicyMismatch, "Executable must be absolute; no PATH resolution is performed.", false)
		}
		if strings.ContainsRune(req.Executable, 0) {
			return *protocol.Denial(req.RequestID, protocol.DecisionDenied, "Executable contains a null byte.", false)
		}
	} else if req.Executable == "" {
		return *protocol.Denial(req.RequestID, protocol.DecisionArtifactUnverified, "Artifact run request is missing stored executable path.", false)
	}
	for _, arg := range req.Argv {
		if strings.ContainsRune(arg, 0) {
			return *protocol.Denial(req.RequestID, protocol.DecisionDenied, "Argument contains a null byte.", false)
		}
	}
	if len(req.Argv) > 128 {
		return *protocol.Denial(req.RequestID, protocol.DecisionScopeTooBroad, "Too many argv entries.", false)
	}

	artifactVerified := false
	runtimeRisks := []string{}
	if req.ArtifactID != "" {
		meta, object, err := b.artifacts.Verify(req.ArtifactID)
		if err != nil {
			return responseFromArtifactError(req.RequestID, err)
		}
		if meta.SHA256 != req.ArtifactSHA256 {
			return *protocol.Denial(req.RequestID, protocol.DecisionArtifactUnverified, "Artifact hash in request does not match stored metadata.", false)
		}
		if object != req.Executable {
			return *protocol.Denial(req.RequestID, protocol.DecisionArtifactUnverified, "Artifact executable path does not match stored object.", false)
		}
		artifactVerified = true
		runtimeRisks = meta.RiskFlags
		if len(runtimeRisks) > 0 {
			return protocol.BrokerResponse{
				RequestID:      req.RequestID,
				Decision:       protocol.DecisionReviewRequired,
				Message:        "Artifact has runtime risk flags that require explicit approval or policy.",
				Retryable:      false,
				ArtifactID:     meta.ID,
				ArtifactSHA256: meta.SHA256,
				Audit:          &protocol.AuditCapture{RuntimeRisks: runtimeRisks},
			}
		}
	}

	effect := policy.InferEffect(req.Executable, req.Argv)
	if req.ArtifactID != "" {
		effect = protocol.EffectReadOnly
	}
	if invalid := policy.ValidateReason(req.Reason, effect, req.Executable, req.Argv); invalid != nil {
		invalid.RequestID = req.RequestID
		return *invalid
	}
	rule, _ := b.policy.Match(req, artifactVerified, runtimeRisks)
	if rule == nil {
		if req.ArtifactID == "" && policy.IsShellExecutable(req.Executable) {
			return protocol.BrokerResponse{
				RequestID: req.RequestID,
				Decision:  protocol.DecisionScopeTooBroad,
				Message:   "Shell execution is denied unless an exact high-risk shell policy exists.",
				Retryable: false,
				Effect:    effect,
			}
		}
		if meta, ok := policy.HasShellMetacharacters(req.Argv); ok {
			return protocol.BrokerResponse{
				RequestID: req.RequestID,
				Decision:  protocol.DecisionScopeTooBroad,
				Message:   fmt.Sprintf("Argument contains shell metacharacter %q and no exact policy allows shell-like syntax.", meta),
				Retryable: false,
				Effect:    effect,
			}
		}
		return protocol.BrokerResponse{
			RequestID: req.RequestID,
			Decision:  protocol.DecisionReviewRequired,
			Message:   "No exact policy matched this request; human review or a policy change is required.",
			Retryable: false,
			Effect:    effect,
		}
	}
	if req.ArtifactID != "" && policy.RuntimeRiskBlocked(rule.Artifact, runtimeRisks) {
		return protocol.BrokerResponse{
			RequestID: req.RequestID,
			Decision:  protocol.DecisionReviewRequired,
			Message:   "Artifact runtime behavior requires approval.",
			Retryable: false,
			PolicyID:  rule.ID,
			Effect:    rule.Effect,
		}
	}
	if rule.Effect != effect && req.ArtifactID == "" {
		return protocol.BrokerResponse{
			RequestID: req.RequestID,
			Decision:  protocol.DecisionPolicyMismatch,
			Message:   fmt.Sprintf("policy.Policy effect %s does not match inferred effect %s.", rule.Effect, effect),
			Retryable: false,
			PolicyID:  rule.ID,
			Effect:    effect,
		}
	}
	if rule.Approval != "not_required" {
		return protocol.BrokerResponse{
			RequestID: req.RequestID,
			Decision:  protocol.DecisionReviewRequired,
			Message:   "Matched policy requires human approval.",
			Retryable: false,
			PolicyID:  rule.ID,
			Effect:    rule.Effect,
		}
	}
	if denied := policy.ShellDenied(req, rule); denied != nil {
		return *denied
	}
	if denied := policy.DeniedEnv(req, rule); denied != nil {
		return *denied
	}
	return b.execute(req, rule, start)
}

func (b *Broker) execute(req protocol.BrokerRequest, rule *policy.PolicyRule, start time.Time) protocol.BrokerResponse {
	timeout := time.Duration(rule.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	limit := rule.OutputLimitBytes
	if limit <= 0 {
		limit = 32768
	}
	stdout := audit.NewCapture(limit)
	stderr := audit.NewCapture(limit)
	cmd := exec.CommandContext(ctx, req.Executable, req.Argv...)
	cmd.Dir = req.CWD
	cmd.Env = policy.SanitizedExecutionEnv(rule.Env)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Run the command in its own process group so a timeout can terminate the
	// whole tree, not just the direct child. On context cancellation the
	// runtime invokes cmd.Cancel instead of killing only cmd.Process.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		signalGroup(cmd)
		return nil
	}
	if err := cmd.Start(); err != nil {
		return protocol.BrokerResponse{
			RequestID: req.RequestID,
			Decision:  protocol.DecisionApproved,
			Message:   "Command failed to start: " + err.Error(),
			PolicyID:  rule.ID,
			Effect:    rule.Effect,
			ExitCode:  127,
			Stdout:    stdout.String(),
			Stderr:    stderr.String(),
			Audit:     captureAudit(stdout, stderr, nil),
		}
	}
	err := cmd.Wait()
	exitCode := 0
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		// Timeout takes priority: a deadline kill makes Wait return a
		// "signal: killed" ExitError whose ExitCode() is -1, so this must be
		// checked before the ExitError branch.
		exitCode = 124
	case err == nil:
		exitCode = 0
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if exitCode <= 0 {
			// Signaled or otherwise non-coded failure.
			exitCode = 1
		}
	}
	msg := "Command executed by exact rootless policy match."
	if ctx.Err() == context.DeadlineExceeded {
		msg = "Command timed out."
	}
	return protocol.BrokerResponse{
		RequestID:      req.RequestID,
		Decision:       protocol.DecisionApproved,
		Message:        msg,
		Retryable:      false,
		PolicyID:       rule.ID,
		Effect:         rule.Effect,
		ExitCode:       exitCode,
		Stdout:         stdout.String(),
		Stderr:         stderr.String(),
		DurationMS:     time.Since(start).Milliseconds(),
		ArtifactID:     req.ArtifactID,
		ArtifactSHA256: req.ArtifactSHA256,
		Audit:          captureAudit(stdout, stderr, nil),
	}
}

// captureAudit derives audit-only statistics from the full (pre-truncation)
// command output tracked by the bounded captures, plus any artifact
// runtime-risk flags observed during evaluation.
func captureAudit(stdout, stderr *audit.Capture, risks []string) *protocol.AuditCapture {
	return &protocol.AuditCapture{
		StdoutSHA256:    stdout.SHA256(),
		StderrSHA256:    stderr.SHA256(),
		StdoutLen:       stdout.Len(),
		StderrLen:       stderr.Len(),
		StdoutTail:      stdout.Tail(512),
		StderrTail:      stderr.Tail(512),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
		RuntimeRisks:    risks,
	}
}

func auditEventFrom(req protocol.BrokerRequest, resp protocol.BrokerResponse, start time.Time) audit.Event {
	exitCode := resp.ExitCode
	hasExit := resp.Decision == protocol.DecisionApproved
	var exitPtr *int
	if hasExit {
		exitPtr = &exitCode
	}
	event := audit.Event{
		SchemaVersion:    1,
		TS:               time.Now(),
		RequestID:        req.RequestID,
		ClientID:         req.ClientID,
		UID:              peer.ObservedOrCurrentUID(req),
		PeerPID:          peer.ObservedOrCurrentPID(req),
		ClientExecutable: req.ClientExecutable,
		CWD:              req.CWD,
		SessionID:        req.SessionID,
		Reason:           req.Reason,
		ArtifactID:       req.ArtifactID,
		ArtifactSHA256:   req.ArtifactSHA256,
		Executable:       req.Executable,
		Argv:             req.Argv,
		Decision:         resp.Decision,
		PolicyID:         resp.PolicyID,
		Effect:           resp.Effect,
		Approval:         approvalFromResponse(resp),
		ExitCode:         exitPtr,
		Timeout:          resp.ExitCode == 124 && resp.Decision == protocol.DecisionApproved,
		DurationMS:       time.Since(start).Milliseconds(),
		Message:          resp.Message,
		Retryable:        resp.Retryable,
		Missing:          resp.Missing,
	}
	if resp.Audit != nil {
		if resp.Audit.StdoutLen > 0 {
			event.StdoutSHA256 = resp.Audit.StdoutSHA256
			event.StdoutLen = resp.Audit.StdoutLen
			event.StdoutTail = resp.Audit.StdoutTail
			event.StdoutTruncated = resp.Audit.StdoutTruncated
		}
		if resp.Audit.StderrLen > 0 {
			event.StderrSHA256 = resp.Audit.StderrSHA256
			event.StderrLen = resp.Audit.StderrLen
			event.StderrTail = resp.Audit.StderrTail
			event.StderrTruncated = resp.Audit.StderrTruncated
		}
		event.RuntimeRiskFlags = resp.Audit.RuntimeRisks
	}
	return event
}

func approvalFromResponse(resp protocol.BrokerResponse) string {
	if resp.Decision == protocol.DecisionApproved {
		return "not_required"
	}
	return ""
}

func responseFromArtifactError(requestID string, err error) protocol.BrokerResponse {
	var re artifact.Error
	if errors.As(err, &re) {
		return *protocol.Denial(requestID, re.Decision, re.Message, re.Decision == protocol.DecisionArtifactUnverified)
	}
	return *protocol.Denial(requestID, protocol.DecisionArtifactUnverified, err.Error(), true)
}

func Send(ctx context.Context, socketPath string, req protocol.BrokerRequest) (protocol.BrokerResponse, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return protocol.BrokerResponse{
			RequestID: req.RequestID,
			Decision:  "BROKER_UNAVAILABLE",
			Message:   "Broker unavailable; no sudo fallback was attempted.",
			Retryable: true,
		}, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return protocol.BrokerResponse{}, err
	}
	var resp protocol.BrokerResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return protocol.BrokerResponse{}, err
	}
	return resp, nil
}

func NewRequestID() string {
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), os.Getpid())
}

func signalGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
