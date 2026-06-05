//go:build devtools

package devtools

import (
	"agent-sudo/internal/artifact"
	"agent-sudo/internal/broker"
	"agent-sudo/internal/config"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/policy"
	"agent-sudo/internal/protocol"
	"agent-sudo/internal/trust"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultRootSmokeDir = "/private/tmp/agent-sudo-root-smoke"
	rootSmokeMarker     = ".agent-sudo-root-smoke"
	rootSmokeClientID   = "root-smoke"
)

type RootSmokeResult struct {
	Status string           `json:"status"`
	Root   string           `json:"root"`
	Checks []RootSmokeCheck `json:"checks"`
}

type RootSmokeCheck struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Decision string `json:"decision,omitempty"`
}

func CmdRootSmoke(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-sudo root-smoke <run|supervise|check|restart|stop|status|cleanup|client-artifact|launchd-dev-status|launchd-dev-diagnose|launchd-dev-install|launchd-dev-check|launchd-dev-uninstall|launchd-dev-cycle>")
	}
	switch args[0] {
	case "run":
		return cmdRootSmokeRun(args[1:], stdout)
	case "supervise":
		return cmdRootSmokeSupervise(args[1:], stdout)
	case "check":
		return cmdRootSmokeCheck(args[1:], stdout)
	case "restart":
		return cmdRootSmokeControl(args[1:], stdout, "restart")
	case "stop":
		return cmdRootSmokeControl(args[1:], stdout, "stop")
	case "status":
		return cmdRootSmokeControl(args[1:], stdout, "status")
	case "cleanup":
		return cmdRootSmokeCleanup(args[1:], stdout)
	case "client-artifact":
		return cmdRootSmokeClientArtifact(args[1:], stdout)
	case "launchd-dev-status", "launchd-dev-diagnose", "launchd-dev-install", "launchd-dev-check", "launchd-dev-uninstall", "launchd-dev-cycle":
		return cmdRootSmokeLaunchdDevControl(args[1:], stdout, args[0])
	default:
		return fmt.Errorf("unknown root-smoke subcommand %q", args[0])
	}
}

func cmdRootSmokeRun(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("root-smoke run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultRootSmokeDir, "disposable root-smoke directory")
	uidFlag := fs.String("uid", os.Getenv("SUDO_UID"), "target client uid")
	gidFlag := fs.String("gid", os.Getenv("SUDO_GID"), "target client gid")
	userFlag := fs.String("user", os.Getenv("SUDO_USER"), "target client username")
	clientPath := fs.String("client-path", "", "agent-sudo binary path used by client")
	keep := fs.Bool("keep", false, "keep disposable tree after run")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	result, err := runRootSmoke(*root, *uidFlag, *gidFlag, *userFlag, *clientPath, *keep)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		printRootSmokeResult(stdout, result)
	}
	if err != nil {
		return err
	}
	if result.Status != "PASS" {
		return errors.New("root-smoke failed")
	}
	return nil
}

func cmdRootSmokeSupervise(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("root-smoke supervise", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultRootSmokeDir, "disposable root-smoke directory")
	uidFlag := fs.String("uid", os.Getenv("SUDO_UID"), "target client uid")
	gidFlag := fs.String("gid", os.Getenv("SUDO_GID"), "target client gid")
	userFlag := fs.String("user", os.Getenv("SUDO_USER"), "target client username")
	clientPath := fs.String("client-path", "", "agent-sudo binary path used by client")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runRootSmokeSupervisor(*root, *uidFlag, *gidFlag, *userFlag, *clientPath, stdout)
}

func cmdRootSmokeCheck(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("root-smoke check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultRootSmokeDir, "disposable root-smoke directory")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	result := runRootSmokeCheck(*root)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		printRootSmokeResult(stdout, result)
	}
	if result.Status != "PASS" {
		return errors.New("root-smoke check failed")
	}
	return nil
}

func cmdRootSmokeControl(args []string, stdout io.Writer, command string) error {
	fs := flag.NewFlagSet("root-smoke "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultRootSmokeDir, "disposable root-smoke directory")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := sendRootSmokeControl(*root, command)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(resp)
	} else {
		printRootSmokeControlResponse(stdout, resp)
	}
	if err != nil {
		return err
	}
	if resp.Status != "OK" {
		return errors.New(resp.Message)
	}
	return nil
}

func cmdRootSmokeLaunchdDevControl(args []string, stdout io.Writer, subcommand string) error {
	command, err := rootSmokeLaunchdDevControlCommand(subcommand)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("root-smoke "+subcommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultRootSmokeDir, "disposable root-smoke directory")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := sendRootSmokeControl(*root, command)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(resp)
	} else {
		printRootSmokeControlResponse(stdout, resp)
	}
	if err != nil {
		return err
	}
	if resp.Status != "OK" {
		return errors.New(resp.Message)
	}
	return nil
}

func rootSmokeLaunchdDevControlCommand(subcommand string) (string, error) {
	switch subcommand {
	case "launchd-dev-status":
		return "launchd-dev-status", nil
	case "launchd-dev-diagnose":
		return "launchd-dev-diagnose", nil
	case "launchd-dev-install":
		return "launchd-dev-install", nil
	case "launchd-dev-check":
		return "launchd-dev-check", nil
	case "launchd-dev-uninstall":
		return "launchd-dev-uninstall", nil
	case "launchd-dev-cycle":
		return "launchd-dev-cycle", nil
	default:
		return "", fmt.Errorf("unknown root-smoke launchd-dev subcommand %q", subcommand)
	}
}

func printRootSmokeControlResponse(stdout io.Writer, resp RootSmokeControlResponse) {
	fmt.Fprintf(stdout, "%s: %s\n", resp.Status, resp.Message)
	if resp.BrokerSocket != "" {
		fmt.Fprintf(stdout, "broker socket: %s\n", resp.BrokerSocket)
	}
	if resp.ControlSocket != "" {
		fmt.Fprintf(stdout, "control socket: %s\n", resp.ControlSocket)
	}
	if resp.Result != nil {
		printLaunchdDevResult(stdout, *resp.Result)
	}
	if resp.LaunchdDev != nil {
		printLaunchdDevDiagnostics(stdout, *resp.LaunchdDev)
	}
}

func cmdRootSmokeCleanup(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("root-smoke cleanup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultRootSmokeDir, "disposable root-smoke directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("root-smoke cleanup must run as root")
	}
	if err := safeRemoveRootSmoke(*root); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %s\n", *root)
	return nil
}

func cmdRootSmokeClientArtifact(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("root-smoke client-artifact", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socketPath := fs.String("socket", "", "broker socket")
	artifactID := fs.String("id", "", "artifact id")
	artifactSHA := fs.String("sha256", "", "artifact sha256")
	executable := fs.String("executable", "", "stored artifact executable")
	clientID := fs.String("client", rootSmokeClientID, "client id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socketPath == "" || *artifactID == "" || *artifactSHA == "" || *executable == "" {
		return errors.New("usage: agent-sudo root-smoke client-artifact --socket <path> --id <id> --sha256 <hash> --executable <path>")
	}
	req := protocol.BrokerRequest{
		SchemaVersion:  1,
		Type:           "command",
		RequestID:      broker.NewRequestID(),
		ClientID:       *clientID,
		CWD:            "/private/tmp",
		Reason:         "Run verified artifact script for broker project target hash verification.",
		Executable:     *executable,
		Argv:           []string{},
		Env:            policy.CollectEnvMetadata(),
		ArtifactID:     *artifactID,
		ArtifactSHA256: *artifactSHA,
	}
	if err := broker.FillClientMetadata(&req); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := broker.Send(ctx, *socketPath, req)
	_ = json.NewEncoder(stdout).Encode(resp)
	if err != nil {
		return err
	}
	if resp.Decision != protocol.DecisionApproved {
		return fmt.Errorf("%s: %s", resp.Decision, resp.Message)
	}
	if resp.ExitCode != 0 {
		return broker.ExitCodeError{Code: resp.ExitCode}
	}
	return nil
}

type RootSmokeControlResponse struct {
	Status         string                 `json:"status"`
	Message        string                 `json:"message"`
	BrokerSocket   string                 `json:"broker_socket,omitempty"`
	ControlSocket  string                 `json:"control_socket,omitempty"`
	ArtifactID     string                 `json:"artifact_id,omitempty"`
	ArtifactSHA256 string                 `json:"artifact_sha256,omitempty"`
	ObjectPath     string                 `json:"object_path,omitempty"`
	Result         *RootSmokeResult       `json:"result,omitempty"`
	LaunchdDev     *LaunchdDevDiagnostics `json:"launchd_dev,omitempty"`
}

func runRootSmoke(root, uidText, gidText, userName, clientPath string, keep bool) (RootSmokeResult, error) {
	result := RootSmokeResult{Status: "PASS", Root: root}
	add := func(id, status, message string) {
		result.Checks = append(result.Checks, RootSmokeCheck{ID: id, Status: status, Message: message})
		if status == "FAIL" {
			result.Status = "FAIL"
		}
	}
	addDecision := func(id, status, message, decision string) {
		result.Checks = append(result.Checks, RootSmokeCheck{ID: id, Status: status, Message: message, Decision: decision})
		if status == "FAIL" {
			result.Status = "FAIL"
		}
	}

	if os.Geteuid() != 0 {
		add("root_required", "FAIL", "root-smoke run must be launched with sudo")
		return result, errors.New("root-smoke run must be launched with sudo")
	}
	uid, gid, userHome, err := resolveSmokeUser(uidText, gidText, userName)
	if err != nil {
		add("target_user", "FAIL", err.Error())
		return result, err
	}
	if clientPath == "" {
		clientPath, err = os.Executable()
		if err != nil {
			add("client_path", "FAIL", err.Error())
			return result, err
		}
	}
	clientPath, err = fsutil.CanonicalClient(clientPath)
	if err != nil {
		add("client_path", "FAIL", err.Error())
		return result, err
	}
	add("target_user", "PASS", fmt.Sprintf("uid=%d gid=%d home=%s", uid, gid, userHome))
	add("client_path", "PASS", clientPath)

	paths, err := prepareRootSmoke(root, uid, gid, clientPath)
	if err != nil {
		add("prepare", "FAIL", err.Error())
		return result, err
	}
	if !keep {
		defer func() {
			_ = safeRemoveRootSmoke(root)
		}()
	}
	add("prepare", "PASS", root)

	preflight := verifyRootSmokeOwnership(paths, gid)
	for _, check := range preflight {
		result.Checks = append(result.Checks, check)
		if check.Status == "FAIL" {
			result.Status = "FAIL"
		}
	}
	if result.Status == "FAIL" {
		return result, errors.New("root-smoke preflight failed")
	}

	b, err := broker.New(paths)
	if err != nil {
		add("broker_load", "FAIL", err.Error())
		return result, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- b.ServeWithOptions(ctx, broker.ServeOptions{
			RunDirMode: 0o750,
			SocketMode: 0o660,
			SocketUID:  0,
			SocketGID:  gid,
		})
	}()
	if err := waitForSocket(paths.SocketPath, errCh); err != nil {
		add("broker_start", "FAIL", err.Error())
		return result, err
	}
	add("broker_start", "PASS", paths.SocketPath)
	for _, check := range verifySocketOwnership(paths.SocketPath, gid) {
		result.Checks = append(result.Checks, check)
		if check.Status == "FAIL" {
			result.Status = "FAIL"
		}
	}
	if result.Status == "FAIL" {
		return result, errors.New("root-smoke socket preflight failed")
	}

	env := clientEnv(paths.SocketPath, userHome, rootSmokeClientID)
	approved, err := runSmokeClientJSON(uid, gid, clientPath, env, "request", "--json", "--client", rootSmokeClientID, "--reason", "Read effective uid for broker project target root-smoke verification.", "--", "/usr/bin/id", "-u")
	if err != nil {
		addDecision("id_returns_root", "FAIL", err.Error(), approved.Decision)
	} else if approved.Decision != protocol.DecisionApproved || approved.ExitCode != 0 || strings.TrimSpace(approved.Stdout) != "0" {
		addDecision("id_returns_root", "FAIL", fmt.Sprintf("unexpected response stdout=%q exit=%d", approved.Stdout, approved.ExitCode), approved.Decision)
	} else {
		addDecision("id_returns_root", "PASS", "normal user client received root execution result", approved.Decision)
	}

	shellResp, _ := runSmokeClientJSON(uid, gid, clientPath, env, "request", "--json", "--client", rootSmokeClientID, "--reason", "Run shell command for broker project target negative test.", "--", "/bin/sh", "-c", "id")
	if shellResp.Decision == protocol.DecisionApproved {
		addDecision("deny_shell", "FAIL", "shell command was approved", shellResp.Decision)
	} else {
		addDecision("deny_shell", "PASS", "shell command denied", shellResp.Decision)
	}

	relativeResp, _ := runSmokeClientJSON(uid, gid, clientPath, env, "request", "--json", "--client", rootSmokeClientID, "--reason", "Read effective uid for broker project target negative test.", "--", "id", "-u")
	if relativeResp.Decision == protocol.DecisionApproved {
		addDecision("deny_relative_executable", "FAIL", "relative executable was approved", relativeResp.Decision)
	} else {
		addDecision("deny_relative_executable", "PASS", "relative executable denied", relativeResp.Decision)
	}

	envResp, _ := runSmokeClientJSON(uid, gid, clientPath, append(env, "LD_PRELOAD=/private/tmp/agent-sudo-fake.dylib"), "request", "--json", "--client", rootSmokeClientID, "--reason", "Read effective uid for broker project target env negative test.", "--", "/usr/bin/id", "-u")
	if envResp.Decision == protocol.DecisionApproved {
		addDecision("deny_env_injection", "FAIL", "LD_PRELOAD request was approved", envResp.Decision)
	} else {
		addDecision("deny_env_injection", "PASS", "LD_PRELOAD request denied", envResp.Decision)
	}

	meta, object, err := createTamperedSmokeArtifact(paths)
	if err != nil {
		add("artifact_tamper_setup", "FAIL", err.Error())
	} else {
		artifactResp, _ := runSmokeClientJSON(uid, gid, clientPath, env, "root-smoke", "client-artifact", "--socket", paths.SocketPath, "--id", meta.ID, "--sha256", meta.SHA256, "--executable", object)
		if artifactResp.Decision != protocol.DecisionArtifactUnverified {
			addDecision("deny_artifact_tamper", "FAIL", "tampered artifact was not rejected", artifactResp.Decision)
		} else {
			addDecision("deny_artifact_tamper", "PASS", "tampered artifact rejected", artifactResp.Decision)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			add("broker_stop", "FAIL", err.Error())
		} else {
			add("broker_stop", "PASS", "temporary broker stopped")
		}
	case <-time.After(2 * time.Second):
		add("broker_stop", "FAIL", "temporary broker did not stop")
	}
	if !keep {
		if err := safeRemoveRootSmoke(root); err != nil {
			add("cleanup", "FAIL", err.Error())
		} else {
			add("cleanup", "PASS", root)
		}
	} else {
		add("cleanup", "PASS", "kept by --keep")
	}
	if result.Status != "PASS" {
		return result, errors.New("root-smoke failed")
	}
	return result, nil
}

func runRootSmokeSupervisor(root, uidText, gidText, userName, clientPath string, stdout io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("root-smoke supervise must be launched with sudo")
	}
	uid, gid, userHome, err := resolveSmokeUser(uidText, gidText, userName)
	if err != nil {
		return err
	}
	if clientPath == "" {
		clientPath, err = os.Executable()
		if err != nil {
			return err
		}
	}
	clientPath, err = fsutil.CanonicalClient(clientPath)
	if err != nil {
		return err
	}
	paths, err := prepareRootSmoke(root, 0, gid, clientPath)
	if err != nil {
		return err
	}
	for _, check := range verifyRootSmokeOwnership(paths, gid) {
		if check.Status == "FAIL" {
			return fmt.Errorf("%s: %s", check.ID, check.Message)
		}
	}

	supervisor := &rootSmokeSupervisor{paths: paths, uid: uid, gid: gid, userHome: userHome, clientPath: clientPath}
	if err := supervisor.start(); err != nil {
		return err
	}
	control, err := startRootSmokeControl(paths, gid, supervisor)
	if err != nil {
		_ = supervisor.stop()
		return err
	}
	defer control.Close()

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	stopByControl := make(chan struct{})
	var closeStop sync.Once
	go acceptRootSmokeControl(ctx, control, supervisor, func() {
		closeStop.Do(func() { close(stopByControl) })
	})

	fmt.Fprintf(stdout, "agent-sudo root-smoke supervisor running\n")
	fmt.Fprintf(stdout, "root: %s\n", paths.Home)
	fmt.Fprintf(stdout, "broker socket: %s\n", paths.SocketPath)
	fmt.Fprintf(stdout, "control socket: %s\n", rootSmokeControlSocket(paths.Home))
	fmt.Fprintf(stdout, "target home: %s\n", userHome)
	fmt.Fprintf(stdout, "normal-user checks: ./agent-sudo root-smoke check\n")
	fmt.Fprintf(stdout, "restart: ./agent-sudo root-smoke restart\n")
	fmt.Fprintf(stdout, "launchd-dev cycle: ./agent-sudo root-smoke launchd-dev-cycle\n")
	fmt.Fprintf(stdout, "launchd-dev diagnose: ./agent-sudo root-smoke launchd-dev-diagnose\n")
	fmt.Fprintf(stdout, "stop: ./agent-sudo root-smoke stop\n")

	select {
	case <-ctx.Done():
	case <-stopByControl:
	}
	_ = supervisor.stop()
	if err := safeRemoveRootSmoke(paths.Home); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "agent-sudo root-smoke supervisor stopped and cleaned up")
	return nil
}

type rootSmokeSupervisor struct {
	paths      config.Paths
	uid        int
	gid        int
	userHome   string
	clientPath string
	mu         sync.Mutex
	launchdMu  sync.Mutex
	cancel     context.CancelFunc
	done       chan error
}

func (s *rootSmokeSupervisor) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return errors.New("broker already running")
	}
	b, err := broker.New(s.paths)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.ServeWithOptions(ctx, broker.ServeOptions{
			RunDirMode: 0o750,
			SocketMode: 0o660,
			SocketUID:  0,
			SocketGID:  s.gid,
		})
	}()
	if err := waitForSocket(s.paths.SocketPath, done); err != nil {
		cancel()
		return err
	}
	s.cancel = cancel
	s.done = done
	return nil
}

func (s *rootSmokeSupervisor) stop() error {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.done = nil
	s.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case err := <-done:
		_ = os.Remove(s.paths.SocketPath)
		return err
	case <-time.After(2 * time.Second):
		return errors.New("broker did not stop")
	}
}

func (s *rootSmokeSupervisor) restart() error {
	if err := s.stop(); err != nil {
		return err
	}
	if err := writeRootSmokeConfig(s.paths, s.clientPath); err != nil {
		return err
	}
	return s.start()
}

func (s *rootSmokeSupervisor) status() RootSmokeControlResponse {
	s.mu.Lock()
	running := s.cancel != nil
	s.mu.Unlock()
	if running {
		return RootSmokeControlResponse{
			Status:        "OK",
			Message:       "root-smoke broker running",
			BrokerSocket:  s.paths.SocketPath,
			ControlSocket: rootSmokeControlSocket(s.paths.Home),
		}
	}
	return RootSmokeControlResponse{Status: "FAIL", Message: "root-smoke broker is not running"}
}

func startRootSmokeControl(paths config.Paths, gid int, supervisor *rootSmokeSupervisor) (net.Listener, error) {
	controlPath := rootSmokeControlSocket(paths.Home)
	if fsutil.PathExists(controlPath) {
		if err := os.Remove(controlPath); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", controlPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(controlPath, 0, gid); err != nil {
		l.Close()
		return nil, err
	}
	if err := os.Chmod(controlPath, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func acceptRootSmokeControl(ctx context.Context, listener net.Listener, supervisor *rootSmokeSupervisor, stop func()) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleRootSmokeControl(conn, supervisor, stop)
	}
}

func handleRootSmokeControl(conn net.Conn, supervisor *rootSmokeSupervisor, stop func()) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(RootSmokeControlResponse{Status: "FAIL", Message: err.Error()})
		return
	}
	command := strings.TrimSpace(string(buf[:n]))
	resp := RootSmokeControlResponse{}
	switch command {
	case "status":
		resp = supervisor.status()
	case "restart":
		if err := supervisor.restart(); err != nil {
			resp = RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
		} else {
			resp = supervisor.status()
			resp.Message = "root-smoke broker restarted"
		}
	case "stop":
		resp = RootSmokeControlResponse{Status: "OK", Message: "root-smoke supervisor stopping"}
		_ = json.NewEncoder(conn).Encode(resp)
		stop()
		return
	case "tamper-artifact":
		meta, object, err := createTamperedSmokeArtifact(supervisor.paths)
		if err != nil {
			resp = RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
		} else {
			resp = RootSmokeControlResponse{
				Status:         "OK",
				Message:        "tampered artifact prepared",
				ArtifactID:     meta.ID,
				ArtifactSHA256: meta.SHA256,
				ObjectPath:     object,
			}
		}
	case "launchd-dev-status":
		resp = supervisor.launchdDevStatus()
	case "launchd-dev-diagnose":
		resp = supervisor.launchdDevDiagnose()
	case "launchd-dev-install":
		resp = supervisor.launchdDevInstall()
	case "launchd-dev-check":
		resp = supervisor.launchdDevCheck()
	case "launchd-dev-uninstall":
		resp = supervisor.launchdDevUninstall()
	case "launchd-dev-cycle":
		resp = supervisor.launchdDevCycle()
	default:
		resp = RootSmokeControlResponse{Status: "FAIL", Message: "unknown control command"}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *rootSmokeSupervisor) launchdDevPlan() (launchdDevPlan, error) {
	return newLaunchdDevPlan(defaultLaunchdDevRoot, defaultLaunchdDevPlistPath, s.gid)
}

func (s *rootSmokeSupervisor) launchdDevDiagnostics(plan launchdDevPlan) LaunchdDevDiagnostics {
	checkClientPath := launchdDevCheckClientPath(plan, s.clientPath)
	return collectLaunchdDevDiagnostics(plan, s.clientPath, checkClientPath)
}

func (s *rootSmokeSupervisor) launchdDevStatus() RootSmokeControlResponse {
	s.launchdMu.Lock()
	defer s.launchdMu.Unlock()
	plan, err := s.launchdDevPlan()
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
	}
	diag := s.launchdDevDiagnostics(plan)
	message := "launchd-dev service missing"
	if diag.Service.Success {
		message = "launchd-dev service loaded"
	}
	return RootSmokeControlResponse{Status: "OK", Message: message, LaunchdDev: &diag}
}

func (s *rootSmokeSupervisor) launchdDevDiagnose() RootSmokeControlResponse {
	s.launchdMu.Lock()
	defer s.launchdMu.Unlock()
	plan, err := s.launchdDevPlan()
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
	}
	diag := s.launchdDevDiagnostics(plan)
	return RootSmokeControlResponse{Status: "OK", Message: "launchd-dev diagnostics collected", LaunchdDev: &diag}
}

func (s *rootSmokeSupervisor) launchdDevInstall() RootSmokeControlResponse {
	s.launchdMu.Lock()
	defer s.launchdMu.Unlock()
	plan, err := s.launchdDevPlan()
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
	}
	result, installErr := installLaunchdDev(plan, s.uid, s.gid, s.userHome, s.clientPath, false)
	diag := s.launchdDevDiagnostics(plan)
	if installErr != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: installErr.Error(), Result: &result, LaunchdDev: &diag}
	}
	return RootSmokeControlResponse{Status: "OK", Message: "launchd-dev installed", Result: &result, LaunchdDev: &diag}
}

func (s *rootSmokeSupervisor) launchdDevCheck() RootSmokeControlResponse {
	s.launchdMu.Lock()
	defer s.launchdMu.Unlock()
	plan, err := s.launchdDevPlan()
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
	}
	result := runLaunchdDevCheck(plan, s.uid, s.gid, s.userHome, s.clientPath)
	diag := s.launchdDevDiagnostics(plan)
	if result.Status != "PASS" {
		return RootSmokeControlResponse{Status: "FAIL", Message: "launchd-dev check failed", Result: &result, LaunchdDev: &diag}
	}
	return RootSmokeControlResponse{Status: "OK", Message: "launchd-dev check passed", Result: &result, LaunchdDev: &diag}
}

func (s *rootSmokeSupervisor) launchdDevUninstall() RootSmokeControlResponse {
	s.launchdMu.Lock()
	defer s.launchdMu.Unlock()
	plan, err := s.launchdDevPlan()
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
	}
	if err := uninstallLaunchdDev(plan); err != nil {
		diag := s.launchdDevDiagnostics(plan)
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error(), LaunchdDev: &diag}
	}
	diag := s.launchdDevDiagnostics(plan)
	return RootSmokeControlResponse{Status: "OK", Message: "launchd-dev uninstalled", LaunchdDev: &diag}
}

func (s *rootSmokeSupervisor) launchdDevCycle() RootSmokeControlResponse {
	s.launchdMu.Lock()
	defer s.launchdMu.Unlock()
	plan, err := s.launchdDevPlan()
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}
	}
	_ = uninstallLaunchdDev(plan)
	result, installErr := installLaunchdDev(plan, s.uid, s.gid, s.userHome, s.clientPath, false)
	if installErr != nil {
		diag := s.launchdDevDiagnostics(plan)
		return RootSmokeControlResponse{Status: "FAIL", Message: installErr.Error(), Result: &result, LaunchdDev: &diag}
	}
	checkResult := runLaunchdDevCheck(plan, s.uid, s.gid, s.userHome, s.clientPath)
	if checkResult.Status != "PASS" {
		diag := s.launchdDevDiagnostics(plan)
		return RootSmokeControlResponse{Status: "FAIL", Message: "launchd-dev cycle check failed", Result: &checkResult, LaunchdDev: &diag}
	}
	if err := uninstallLaunchdDev(plan); err != nil {
		diag := s.launchdDevDiagnostics(plan)
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error(), Result: &checkResult, LaunchdDev: &diag}
	}
	diag := s.launchdDevDiagnostics(plan)
	return RootSmokeControlResponse{Status: "OK", Message: "launchd-dev full cycle passed", Result: &checkResult, LaunchdDev: &diag}
}

func runRootSmokeCheck(root string) RootSmokeResult {
	result := RootSmokeResult{Status: "PASS", Root: root}
	add := func(id, status, message string) {
		result.Checks = append(result.Checks, RootSmokeCheck{ID: id, Status: status, Message: message})
		if status == "FAIL" {
			result.Status = "FAIL"
		}
	}
	addDecision := func(id, status, message, decision string) {
		result.Checks = append(result.Checks, RootSmokeCheck{ID: id, Status: status, Message: message, Decision: decision})
		if status == "FAIL" {
			result.Status = "FAIL"
		}
	}
	paths := rootSmokePaths(root)
	status, err := sendRootSmokeControl(root, "status")
	if err != nil {
		add("supervisor_status", "FAIL", err.Error())
		return result
	}
	if status.Status != "OK" {
		add("supervisor_status", "FAIL", status.Message)
		return result
	}
	add("supervisor_status", "PASS", status.Message)

	approved := sendRootSmokeDirect(paths.SocketPath, "/usr/bin/id", []string{"-u"}, "Read effective uid for broker project target root-smoke verification.", nil, "", "")
	if approved.Decision != protocol.DecisionApproved || approved.ExitCode != 0 || strings.TrimSpace(approved.Stdout) != "0" {
		addDecision("id_returns_root", "FAIL", fmt.Sprintf("unexpected response stdout=%q exit=%d", approved.Stdout, approved.ExitCode), approved.Decision)
	} else {
		addDecision("id_returns_root", "PASS", "normal user client received root execution result", approved.Decision)
	}

	shellResp := sendRootSmokeDirect(paths.SocketPath, "/bin/sh", []string{"-c", "id"}, "Run shell command for broker project target negative test.", nil, "", "")
	if shellResp.Decision == protocol.DecisionApproved {
		addDecision("deny_shell", "FAIL", "shell command was approved", shellResp.Decision)
	} else {
		addDecision("deny_shell", "PASS", "shell command denied", shellResp.Decision)
	}

	relativeResp := sendRootSmokeDirect(paths.SocketPath, "id", []string{"-u"}, "Read effective uid for broker project target negative test.", nil, "", "")
	if relativeResp.Decision == protocol.DecisionApproved {
		addDecision("deny_relative_executable", "FAIL", "relative executable was approved", relativeResp.Decision)
	} else {
		addDecision("deny_relative_executable", "PASS", "relative executable denied", relativeResp.Decision)
	}

	envResp := sendRootSmokeDirect(paths.SocketPath, "/usr/bin/id", []string{"-u"}, "Read effective uid for broker project target env negative test.", map[string]string{"LD_PRELOAD": "[present]"}, "", "")
	if envResp.Decision == protocol.DecisionApproved {
		addDecision("deny_env_injection", "FAIL", "LD_PRELOAD request was approved", envResp.Decision)
	} else {
		addDecision("deny_env_injection", "PASS", "LD_PRELOAD request denied", envResp.Decision)
	}

	artifact, err := sendRootSmokeControl(root, "tamper-artifact")
	if err != nil || artifact.Status != "OK" {
		if err != nil {
			add("artifact_tamper_setup", "FAIL", err.Error())
		} else {
			add("artifact_tamper_setup", "FAIL", artifact.Message)
		}
		return result
	}
	artifactResp := sendRootSmokeDirect(paths.SocketPath, artifact.ObjectPath, nil, "Run verified artifact script for broker project target hash verification.", nil, artifact.ArtifactID, artifact.ArtifactSHA256)
	if artifactResp.Decision != protocol.DecisionArtifactUnverified {
		addDecision("deny_artifact_tamper", "FAIL", "tampered artifact was not rejected", artifactResp.Decision)
	} else {
		addDecision("deny_artifact_tamper", "PASS", "tampered artifact rejected", artifactResp.Decision)
	}
	return result
}

func sendRootSmokeDirect(socketPath, executable string, argv []string, reason string, env map[string]string, artifactID, artifactSHA string) protocol.BrokerResponse {
	if env == nil {
		env = policy.CollectEnvMetadata()
	}
	req := protocol.BrokerRequest{
		SchemaVersion:  1,
		Type:           "command",
		RequestID:      broker.NewRequestID(),
		ClientID:       rootSmokeClientID,
		CWD:            "/private/tmp",
		Reason:         reason,
		Executable:     executable,
		Argv:           argv,
		Env:            env,
		ArtifactID:     artifactID,
		ArtifactSHA256: artifactSHA,
	}
	if err := broker.FillClientMetadata(&req); err != nil {
		return protocol.BrokerResponse{RequestID: req.RequestID, Decision: "CLIENT_METADATA_ERROR", Message: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := broker.Send(ctx, socketPath, req)
	if err != nil && resp.Decision == "" {
		return protocol.BrokerResponse{RequestID: req.RequestID, Decision: "BROKER_UNAVAILABLE", Message: err.Error(), Retryable: true}
	}
	return resp
}

func rootSmokeControlSocket(root string) string {
	return filepath.Join(root, "run", "control.sock")
}

func sendRootSmokeControl(root, command string) (RootSmokeControlResponse, error) {
	controlPath := rootSmokeControlSocket(root)
	conn, err := net.DialTimeout("unix", controlPath, 2*time.Second)
	if err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}, err
	}
	var resp RootSmokeControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return RootSmokeControlResponse{Status: "FAIL", Message: err.Error()}, err
	}
	return resp, nil
}

func printRootSmokeResult(w io.Writer, result RootSmokeResult) {
	fmt.Fprintf(w, "agent-sudo root-smoke: %s\nroot: %s\n", result.Status, result.Root)
	for _, check := range result.Checks {
		if check.Decision != "" {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", check.Status, check.ID, check.Decision, check.Message)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\n", check.Status, check.ID, check.Message)
		}
	}
}

func rootSmokePaths(root string) config.Paths {
	return config.Paths{
		Home:        root,
		RunDir:      filepath.Join(root, "run"),
		SocketPath:  filepath.Join(root, "run", "broker.sock"),
		ConfigDir:   filepath.Join(root, "config"),
		PolicyPath:  filepath.Join(root, "config", "policy.yaml"),
		TrustPath:   filepath.Join(root, "config", "trust.json"),
		StateDir:    filepath.Join(root, "state"),
		AuditPath:   filepath.Join(root, "audit", "audit.jsonl"),
		ArtifactDir: filepath.Join(root, "artifacts"),
	}
}

func prepareRootSmoke(root string, uid, gid int, clientPath string) (config.Paths, error) {
	root, err := cleanRootSmokePath(root)
	if err != nil {
		return config.Paths{}, err
	}
	if fsutil.PathExists(root) {
		if err := safeRemoveRootSmoke(root); err != nil {
			return config.Paths{}, err
		}
	}
	paths := rootSmokePaths(root)
	if err := mkdirOwned(root, 0o755, 0, 0); err != nil {
		return config.Paths{}, err
	}
	if err := os.WriteFile(filepath.Join(root, rootSmokeMarker), []byte("agent-sudo root smoke disposable tree\n"), 0o600); err != nil {
		return config.Paths{}, err
	}
	if err := os.Chown(filepath.Join(root, rootSmokeMarker), 0, 0); err != nil {
		return config.Paths{}, err
	}
	if err := mkdirOwned(paths.RunDir, 0o750, 0, gid); err != nil {
		return config.Paths{}, err
	}
	if err := mkdirOwned(paths.ConfigDir, 0o700, 0, 0); err != nil {
		return config.Paths{}, err
	}
	if err := mkdirOwned(paths.StateDir, 0o700, 0, 0); err != nil {
		return config.Paths{}, err
	}
	if err := mkdirOwned(filepath.Dir(paths.AuditPath), 0o700, 0, 0); err != nil {
		return config.Paths{}, err
	}
	if err := mkdirOwned(paths.ArtifactDir, 0o700, 0, 0); err != nil {
		return config.Paths{}, err
	}
	if err := writeRootSmokeConfig(paths, clientPath); err != nil {
		return config.Paths{}, err
	}
	return paths, nil
}

func writeRootSmokeConfig(paths config.Paths, clientPath string) error {
	policy := rootSmokePolicy()
	if err := writeRootOwnedJSON(paths.PolicyPath, policy, 0o600); err != nil {
		return err
	}
	client, err := trust.ClientForPath(rootSmokeClientID, clientPath)
	if err != nil {
		return err
	}
	trust := trust.Store{
		Version: 1,
		Clients: []trust.Client{client},
	}
	if err := writeRootOwnedJSON(paths.TrustPath, trust, 0o600); err != nil {
		return err
	}
	return nil
}

func rootSmokePolicy() policy.Policy {
	return policy.Policy{
		Version: 1,
		Rules: []policy.PolicyRule{
			{
				ID:               "root-smoke.id-u",
				Clients:          []string{rootSmokeClientID},
				Executable:       "/usr/bin/id",
				Argv:             []policy.ArgMatcher{exactMatcher("-u")},
				Effect:           protocol.EffectReadOnly,
				Approval:         "not_required",
				TimeoutSeconds:   5,
				OutputLimitBytes: 1024,
			},
			{
				ID:               "root-smoke.artifact.verified",
				Clients:          []string{rootSmokeClientID},
				Argv:             []policy.ArgMatcher{},
				Effect:           protocol.EffectReadOnly,
				Approval:         "not_required",
				Artifact:         policy.ArtifactPolicy{AllowVerified: true},
				TimeoutSeconds:   5,
				OutputLimitBytes: 1024,
			},
		},
	}
}

func exactMatcher(s string) policy.ArgMatcher {
	return policy.ArgMatcher{Exact: &s}
}

func writeRootOwnedJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), mode); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func mkdirOwned(path string, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func cleanRootSmokePath(root string) (string, error) {
	cleaned := filepath.Clean(root)
	if cleaned != defaultRootSmokeDir && !strings.HasPrefix(cleaned, defaultRootSmokeDir+"-") {
		return "", fmt.Errorf("refusing root-smoke path outside %s*", defaultRootSmokeDir)
	}
	return cleaned, nil
}

func safeRemoveRootSmoke(root string) error {
	cleaned, err := cleanRootSmokePath(root)
	if err != nil {
		return err
	}
	if !fsutil.PathExists(cleaned) {
		return nil
	}
	marker := filepath.Join(cleaned, rootSmokeMarker)
	if !fsutil.PathExists(marker) {
		return fmt.Errorf("refusing to remove %s without %s marker", cleaned, rootSmokeMarker)
	}
	return os.RemoveAll(cleaned)
}

func resolveSmokeUser(uidText, gidText, userName string) (int, int, string, error) {
	if uidText == "" || gidText == "" {
		return 0, 0, "", errors.New("target uid/gid are required; run via sudo or pass --uid and --gid")
	}
	uid64, err := strconv.ParseInt(uidText, 10, 32)
	if err != nil {
		return 0, 0, "", fmt.Errorf("invalid uid %q: %w", uidText, err)
	}
	gid64, err := strconv.ParseInt(gidText, 10, 32)
	if err != nil {
		return 0, 0, "", fmt.Errorf("invalid gid %q: %w", gidText, err)
	}
	home := "/private/tmp"
	if userName != "" {
		if u, err := user.Lookup(userName); err == nil && u.HomeDir != "" {
			home = u.HomeDir
		}
	} else if u, err := user.LookupId(uidText); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	return int(uid64), int(gid64), home, nil
}

func verifyRootSmokeOwnership(paths config.Paths, targetGID int) []RootSmokeCheck {
	checks := []RootSmokeCheck{}
	checks = append(checks, verifyPath("root_dir", paths.Home, 0, -1, 0o755, true))
	checks = append(checks, verifyPath("run_dir", paths.RunDir, 0, targetGID, 0o750, true))
	checks = append(checks, verifyPath("config_dir", paths.ConfigDir, 0, 0, 0o700, true))
	checks = append(checks, verifyPath("policy_file", paths.PolicyPath, 0, 0, 0o600, false))
	checks = append(checks, verifyPath("trust_file", paths.TrustPath, 0, 0, 0o600, false))
	checks = append(checks, verifyPath("audit_dir", filepath.Dir(paths.AuditPath), 0, 0, 0o700, true))
	checks = append(checks, verifyPath("artifact_dir", paths.ArtifactDir, 0, 0, 0o700, true))
	return checks
}

func verifySocketOwnership(socketPath string, targetGID int) []RootSmokeCheck {
	return []RootSmokeCheck{verifyPath("socket", socketPath, 0, targetGID, 0o660, false)}
}

func verifyPath(id, path string, wantUID, wantGID int, wantMode os.FileMode, wantDir bool) RootSmokeCheck {
	info, err := os.Lstat(path)
	if err != nil {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: err.Error()}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: path + " is a symlink"}
	}
	if wantDir && !info.IsDir() {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: path + " is not a directory"}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: "stat ownership unavailable for " + path}
	}
	if int(st.Uid) != wantUID {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: fmt.Sprintf("%s uid=%d want=%d", path, st.Uid, wantUID)}
	}
	if wantGID >= 0 && int(st.Gid) != wantGID {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: fmt.Sprintf("%s gid=%d want=%d", path, st.Gid, wantGID)}
	}
	if info.Mode().Perm() != wantMode {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: fmt.Sprintf("%s mode=%#o want=%#o", path, info.Mode().Perm(), wantMode)}
	}
	if info.Mode().Perm()&0o002 != 0 {
		return RootSmokeCheck{ID: id, Status: "FAIL", Message: path + " is world-writable"}
	}
	return RootSmokeCheck{ID: id, Status: "PASS", Message: path}
}

func waitForSocket(path string, errCh <-chan error) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fsutil.PathExists(path) {
			return nil
		}
		select {
		case err := <-errCh:
			return err
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
	return errors.New("broker socket did not appear")
}

// clientEnv builds the sanitized environment a disposable test client uses to
// reach a broker socket. It is shared by the root-smoke and launchd-dev flows,
// which differ only in the enrolled client id.
func clientEnv(socketPath, home, clientID string) []string {
	return []string{
		"AGENT_SUDO_SOCKET=" + socketPath,
		"AGENT_SUDO_CLIENT_ID=" + clientID,
		"HOME=" + home,
		"TMPDIR=/private/tmp",
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	}
}

func runSmokeClientJSON(uid, gid int, clientPath string, env []string, args ...string) (protocol.BrokerResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, clientPath, args...)
	cmd.Env = env
	cmd.Dir = "/private/tmp"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var resp protocol.BrokerResponse
	if out.Len() > 0 {
		_ = json.Unmarshal(out.Bytes(), &resp)
	}
	if resp.Decision == "" {
		resp.Message = strings.TrimSpace(errOut.String())
	}
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func createTamperedSmokeArtifact(paths config.Paths) (artifact.Metadata, string, error) {
	store := artifact.NewStore(paths.ArtifactDir)
	content := []byte("#!/bin/sh\necho should-not-run\n")
	meta, err := store.StoreContent(content, artifact.Metadata{
		SourceType: "root_smoke",
		ImportedAt: time.Now(),
	})
	if err != nil {
		return artifact.Metadata{}, "", err
	}
	object := store.ObjectPath(meta.SHA256)
	if err := os.Chmod(object, 0o700); err != nil {
		return artifact.Metadata{}, "", err
	}
	if err := os.WriteFile(object, []byte("#!/bin/sh\necho tampered\n"), 0o700); err != nil {
		return artifact.Metadata{}, "", err
	}
	if err := os.Chown(object, 0, 0); err != nil {
		return artifact.Metadata{}, "", err
	}
	return meta, object, nil
}
