// Package cli implements the agent-sudo command-line dispatch and the
// individual user-facing subcommands. The dev-only harness subcommands are
// registered at init time via RegisterCommand when the binary is built with
// -tags devtools, so the production binary contains only the commands below.
package cli

import (
	"agent-sudo/internal/artifact"
	"agent-sudo/internal/audit"
	"agent-sudo/internal/broker"
	"agent-sudo/internal/config"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/policy"
	"agent-sudo/internal/protocol"
	"agent-sudo/internal/selftest"
	"agent-sudo/internal/trust"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CommandFunc is the signature of a top-level subcommand handler.
type CommandFunc func(args []string, stdout, stderr io.Writer) error

// extraCommands holds optional subcommands registered at init time, used by the
// dev-only harness when the binary is built with -tags devtools.
var extraCommands = map[string]CommandFunc{}

// RegisterCommand adds an optional top-level subcommand. It is intended to be
// called from a build-tagged init in the cmd entrypoint, keeping dev tooling out
// of the production binary.
func RegisterCommand(name string, fn CommandFunc) {
	extraCommands[name] = fn
}

// Run dispatches a single agent-sudo invocation and returns any error.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}
	paths, err := config.DefaultPaths()
	if err != nil {
		return err
	}
	switch args[0] {
	case "install":
		return cmdInstall(paths, args[1:], stdout)
	case "status":
		return cmdStatus(paths, stdout)
	case "broker":
		return cmdBroker(paths, args[1:], stdout)
	case "request":
		return cmdRequest(paths, args[1:], stdout, stderr)
	case "trust":
		return cmdTrust(paths, args[1:], stdout)
	case "policy":
		return cmdPolicy(paths, args[1:], stdout)
	case "artifact":
		return cmdArtifact(paths, args[1:], stdout, stderr)
	case "fetch":
		return cmdFetch(paths, args[1:], stdout)
	case "audit":
		return cmdAudit(paths, args[1:], stdout)
	case "self-test":
		return cmdSelfTest(paths, args[1:], stdout)
	default:
		if fn, ok := extraCommands[args[0]]; ok {
			return fn(args[1:], stdout, stderr)
		}
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	cmds := "install|status|broker|request|trust|policy|fetch|artifact|audit|self-test"
	if extra := extraCommandNames(); extra != "" {
		cmds += "|" + extra
	}
	fmt.Fprintf(w, "usage: agent-sudo <%s> ...\n", cmds)
}

func extraCommandNames() string {
	names := make([]string, 0, len(extraCommands))
	for name := range extraCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "|")
}

func cmdInstall(paths config.Paths, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, dir := range []string{paths.RunDir, paths.ConfigDir, paths.StateDir, paths.ArtifactDir} {
		if err := fsutil.EnsurePrivateDir(dir); err != nil {
			return err
		}
	}
	if err := policy.SaveDefaultPolicy(paths.PolicyPath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Initialized rootless agent-sudo paths.\nsocket: %s\npolicy: %s\naudit: %s\n", paths.SocketPath, paths.PolicyPath, paths.AuditPath)
	return nil
}

func cmdStatus(paths config.Paths, stdout io.Writer) error {
	fmt.Fprintf(stdout, "socket: %s (%s)\n", paths.SocketPath, existsLabel(paths.SocketPath))
	fmt.Fprintf(stdout, "policy: %s (%s)\n", paths.PolicyPath, existsLabel(paths.PolicyPath))
	fmt.Fprintf(stdout, "trust: %s (%s)\n", paths.TrustPath, existsLabel(paths.TrustPath))
	fmt.Fprintf(stdout, "audit: %s (%s)\n", paths.AuditPath, existsLabel(paths.AuditPath))
	return nil
}

func existsLabel(path string) string {
	if fsutil.PathExists(path) {
		return "present"
	}
	return "missing"
}

func cmdBroker(paths config.Paths, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "serve" {
		return errors.New("usage: agent-sudo broker serve")
	}
	fs := flag.NewFlagSet("broker serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	runDirModeText := fs.String("run-dir-mode", "0700", "run directory mode")
	socketModeText := fs.String("socket-mode", "0600", "socket mode")
	socketUID := fs.Int("socket-uid", -1, "socket uid")
	socketGID := fs.Int("socket-gid", -1, "socket gid")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	runDirMode, err := parseFileMode(*runDirModeText)
	if err != nil {
		return fmt.Errorf("invalid --run-dir-mode: %w", err)
	}
	socketMode, err := parseFileMode(*socketModeText)
	if err != nil {
		return fmt.Errorf("invalid --socket-mode: %w", err)
	}
	b, err := broker.New(paths)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "agent-sudo broker listening on %s\n", paths.SocketPath)
	return b.ServeWithOptions(ctx, broker.ServeOptions{
		RunDirMode: runDirMode,
		SocketMode: socketMode,
		SocketUID:  *socketUID,
		SocketGID:  *socketGID,
	})
}

func parseFileMode(text string) (os.FileMode, error) {
	if text == "" {
		return 0, errors.New("empty mode")
	}
	value, err := strconv.ParseUint(text, 0, 32)
	if err != nil {
		return 0, err
	}
	if value > 0o777 {
		return 0, fmt.Errorf("mode %#o exceeds 0777", value)
	}
	return os.FileMode(value), nil
}

func cmdRequest(paths config.Paths, args []string, stdout, stderr io.Writer) error {
	req, jsonOut, err := buildCommandRequest(args, "", "")
	if err != nil {
		return err
	}
	if err := broker.FillClientMetadata(&req); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := broker.Send(ctx, paths.SocketPath, req)
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(resp)
	} else {
		printResponse(stdout, stderr, resp)
	}
	if err != nil {
		return errors.New(resp.Message)
	}
	if resp.Decision != protocol.DecisionApproved {
		return fmt.Errorf("%s: %s", resp.Decision, resp.Message)
	}
	if resp.ExitCode != 0 {
		return broker.ExitCodeError{Code: resp.ExitCode}
	}
	return nil
}

func buildCommandRequest(args []string, artifactID, artifactHash string) (protocol.BrokerRequest, bool, error) {
	before, cmdArgs, ok := splitAtSeparator(args)
	if !ok {
		return protocol.BrokerRequest{}, false, errors.New("usage: agent-sudo request --reason <text> -- <absolute command> [args...]")
	}
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "reason")
	session := fs.String("session", "", "session id")
	client := fs.String("client", config.EnvOrDefault("AGENT_SUDO_CLIENT_ID", "codex"), "client id")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(before); err != nil {
		return protocol.BrokerRequest{}, false, err
	}
	if artifactID == "" && len(cmdArgs) == 0 {
		return protocol.BrokerRequest{}, false, errors.New("missing command after --")
	}
	executable := ""
	argv := []string{}
	if artifactID == "" {
		executable = cmdArgs[0]
		argv = cmdArgs[1:]
	} else {
		argv = cmdArgs
	}
	cwd, err := os.Getwd()
	if err != nil {
		return protocol.BrokerRequest{}, false, err
	}
	req := protocol.BrokerRequest{
		SchemaVersion:  1,
		Type:           "command",
		RequestID:      broker.NewRequestID(),
		ClientID:       *client,
		CWD:            cwd,
		SessionID:      *session,
		Reason:         *reason,
		Executable:     executable,
		Argv:           argv,
		Env:            policy.CollectEnvMetadata(),
		ArtifactID:     artifactID,
		ArtifactSHA256: artifactHash,
	}
	return req, *jsonOut, nil
}

func splitAtSeparator(args []string) ([]string, []string, bool) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

func printResponse(stdout, stderr io.Writer, resp protocol.BrokerResponse) {
	if resp.Stdout != "" {
		fmt.Fprint(stdout, resp.Stdout)
	}
	if resp.Stderr != "" {
		fmt.Fprint(stderr, resp.Stderr)
	}
	if resp.Decision != protocol.DecisionApproved {
		fmt.Fprintf(stderr, "%s: %s\n", resp.Decision, resp.Message)
		if resp.Retryable && resp.SuggestedReasonShape != "" {
			fmt.Fprintf(stderr, "retryable: %t\nsuggested_reason_shape: %s\n", resp.Retryable, resp.SuggestedReasonShape)
		}
	}
}

func cmdTrust(paths config.Paths, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-sudo trust <add|list> ...")
	}
	switch args[0] {
	case "add":
		id, path, err := parseTrustAddArgs(args[1:])
		if err != nil {
			return err
		}
		if id == "" || path == "" {
			return errors.New("usage: agent-sudo trust add <client-id> --path <absolute-path>")
		}
		client, err := trust.AddClient(paths.TrustPath, id, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "trusted %s %s %s\n", client.ID, client.Path, client.SHA256)
		return nil
	case "list":
		store, err := trust.Load(paths.TrustPath)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(store)
	default:
		return fmt.Errorf("unknown trust subcommand %q", args[0])
	}
}

func parseTrustAddArgs(args []string) (string, string, error) {
	var id string
	var path string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 >= len(args) {
				return "", "", errors.New("--path requires a value")
			}
			path = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return "", "", fmt.Errorf("unknown trust add flag %q", args[i])
			}
			if id != "" {
				return "", "", fmt.Errorf("unexpected trust add argument %q", args[i])
			}
			id = args[i]
		}
	}
	return id, path, nil
}

func cmdPolicy(paths config.Paths, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-sudo policy <list|test>")
	}
	pol, err := policy.LoadPolicy(paths.PolicyPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return json.NewEncoder(stdout).Encode(pol)
	case "test":
		req, _, err := buildCommandRequest(args[1:], "", "")
		if err != nil {
			return err
		}
		effect := policy.InferEffect(req.Executable, req.Argv)
		rule, _ := pol.Match(req, false, nil)
		if rule == nil {
			fmt.Fprintf(stdout, "%s effect=%s\n", protocol.DecisionReviewRequired, effect)
			return nil
		}
		fmt.Fprintf(stdout, "%s policy_id=%s effect=%s approval=%s\n", protocol.DecisionApproved, rule.ID, rule.Effect, rule.Approval)
		return nil
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

func cmdFetch(paths config.Paths, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rawURL := fs.String("url", "", "url")
	expected := fs.String("sha256", "", "sha256")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rawURL == "" || *expected == "" {
		return errors.New("usage: agent-sudo fetch --url <https-url> --sha256 <hash>")
	}
	store := artifact.NewStore(paths.ArtifactDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	meta, err := store.Fetch(ctx, *rawURL, *expected, http.DefaultClient, 10<<20)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(meta)
}

func cmdArtifact(paths config.Paths, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-sudo artifact <import|inspect|run> ...")
	}
	store := artifact.NewStore(paths.ArtifactDir)
	switch args[0] {
	case "import":
		if len(args) != 2 {
			return errors.New("usage: agent-sudo artifact import <path>")
		}
		meta, err := store.Import(args[1])
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(meta)
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: agent-sudo artifact inspect <artifact-id>")
		}
		meta, object, err := store.Verify(args[1])
		if err != nil {
			return err
		}
		type inspectResponse struct {
			artifact.Metadata
			ObjectPath string `json:"object_path"`
			Verified   bool   `json:"verified"`
		}
		return json.NewEncoder(stdout).Encode(inspectResponse{Metadata: meta, ObjectPath: object, Verified: true})
	case "run":
		return cmdArtifactRun(paths, store, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown artifact subcommand %q", args[0])
	}
}

func cmdArtifactRun(paths config.Paths, store artifact.Store, args []string, stdout, stderr io.Writer) error {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	before := args
	after := []string{}
	if separator >= 0 {
		before = args[:separator]
		after = args[separator+1:]
	}
	fs := flag.NewFlagSet("artifact run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "reason")
	session := fs.String("session", "", "session id")
	client := fs.String("client", config.EnvOrDefault("AGENT_SUDO_CLIENT_ID", "codex"), "client id")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(before); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New("usage: agent-sudo artifact run --reason <text> <artifact-id> [-- args...]")
	}
	meta, object, err := store.Verify(rest[0])
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	req := protocol.BrokerRequest{
		SchemaVersion:  1,
		Type:           "command",
		RequestID:      broker.NewRequestID(),
		ClientID:       *client,
		CWD:            cwd,
		SessionID:      *session,
		Reason:         *reason,
		Executable:     object,
		Argv:           after,
		Env:            policy.CollectEnvMetadata(),
		ArtifactID:     meta.ID,
		ArtifactSHA256: meta.SHA256,
	}
	if err := broker.FillClientMetadata(&req); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := broker.Send(ctx, paths.SocketPath, req)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(resp)
	} else {
		printResponse(stdout, stderr, resp)
	}
	if err != nil {
		return errors.New(resp.Message)
	}
	if resp.Decision != protocol.DecisionApproved {
		return fmt.Errorf("%s: %s", resp.Decision, resp.Message)
	}
	if resp.ExitCode != 0 {
		return broker.ExitCodeError{Code: resp.ExitCode}
	}
	return nil
}

func cmdAudit(paths config.Paths, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-sudo audit <tail|show>")
	}
	switch args[0] {
	case "tail":
		lines, err := audit.Tail(paths.AuditPath, 20)
		if err != nil {
			return err
		}
		for _, line := range lines {
			fmt.Fprintln(stdout, line)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return errors.New("usage: agent-sudo audit show <request-id>")
		}
		event, err := audit.Show(paths.AuditPath, args[1])
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(event)
	default:
		return fmt.Errorf("unknown audit subcommand %q", args[0])
	}
}

func cmdSelfTest(paths config.Paths, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("self-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	result := selftest.Run(paths)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		fmt.Fprintf(stdout, "agent-sudo self-test: %s\n", result.Status)
		for _, check := range result.Checks {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", check.Status, check.ID, check.Message)
		}
	}
	if result.Status == "FAIL" {
		return errors.New("self-test failed")
	}
	return nil
}
