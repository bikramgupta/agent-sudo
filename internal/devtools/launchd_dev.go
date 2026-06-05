//go:build devtools

package devtools

import (
	"agent-sudo/internal/audit"
	"agent-sudo/internal/config"
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/policy"
	"agent-sudo/internal/protocol"
	"agent-sudo/internal/trust"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultLaunchdDevRoot      = "/private/tmp/agent-sudo-launchd-dev"
	launchdDevMarker           = ".agent-sudo-launchd-dev"
	launchdDevLabel            = "com.bikram.agent-sudo.dev"
	defaultLaunchdDevPlistPath = "/Library/LaunchDaemons/com.bikram.agent-sudo.dev.plist"
	launchdDevClientID         = "launchd-dev"
)

type launchdDevPlan struct {
	Root             string
	Paths            config.Paths
	Label            string
	PlistPath        string
	BinaryPath       string
	StdoutPath       string
	StderrPath       string
	ProgramArguments []string
	Environment      map[string]string
	SocketGID        int
}

type LaunchdDevDiagnostics struct {
	Label               string                       `json:"label"`
	Root                string                       `json:"root"`
	PlistPath           string                       `json:"plist_path"`
	SocketPath          string                       `json:"socket_path"`
	AuditPath           string                       `json:"audit_path"`
	Service             LaunchdDevCommandDiagnostic  `json:"service"`
	Paths               []LaunchdDevPathDiagnostic   `json:"paths"`
	Trust               []LaunchdDevTrustDiagnostic  `json:"trust"`
	ExpectedCheckClient LaunchdDevBinaryDiagnostic   `json:"expected_check_client"`
	Binaries            []LaunchdDevBinaryDiagnostic `json:"binaries"`
	Audit               LaunchdDevFileTail           `json:"audit"`
	Logs                []LaunchdDevFileTail         `json:"logs"`
}

type LaunchdDevCommandDiagnostic struct {
	Args       []string `json:"args"`
	Success    bool     `json:"success"`
	OutputTail []string `json:"output_tail,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type LaunchdDevPathDiagnostic struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	IsDir    bool   `json:"is_dir,omitempty"`
	Mode     string `json:"mode,omitempty"`
	UID      int    `json:"uid,omitempty"`
	GID      int    `json:"gid,omitempty"`
	WantMode string `json:"want_mode,omitempty"`
	WantUID  int    `json:"want_uid,omitempty"`
	WantGID  int    `json:"want_gid,omitempty"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Error    string `json:"error,omitempty"`
}

type LaunchdDevTrustDiagnostic struct {
	ID           string `json:"id"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Exists       bool   `json:"exists"`
	ActualSHA256 string `json:"actual_sha256,omitempty"`
	MatchesFile  bool   `json:"matches_file"`
	Error        string `json:"error,omitempty"`
}

type LaunchdDevBinaryDiagnostic struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   string `json:"mode,omitempty"`
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
	Error  string `json:"error,omitempty"`
}

type LaunchdDevFileTail struct {
	ID     string   `json:"id"`
	Path   string   `json:"path"`
	Exists bool     `json:"exists"`
	Lines  []string `json:"lines,omitempty"`
	Error  string   `json:"error,omitempty"`
}

func CmdLaunchdDev(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: agent-sudo launchd-dev <install|status|check|restart|uninstall>")
	}
	switch args[0] {
	case "install":
		return cmdLaunchdDevInstall(args[1:], stdout)
	case "status":
		return cmdLaunchdDevStatus(args[1:], stdout)
	case "check":
		return cmdLaunchdDevCheck(args[1:], stdout)
	case "restart":
		return cmdLaunchdDevRestart(args[1:], stdout)
	case "uninstall":
		return cmdLaunchdDevUninstall(args[1:], stdout)
	default:
		return fmt.Errorf("unknown launchd-dev subcommand %q", args[0])
	}
}

func cmdLaunchdDevInstall(args []string, stdout io.Writer) error {
	return runLaunchdDevInstall(args, stdout, "installed")
}

func cmdLaunchdDevRestart(args []string, stdout io.Writer) error {
	return runLaunchdDevInstall(args, stdout, "restarted")
}

func runLaunchdDevInstall(args []string, stdout io.Writer, verb string) error {
	fs := flag.NewFlagSet("launchd-dev "+verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultLaunchdDevRoot, "disposable launchd-dev root")
	plistPath := fs.String("plist", defaultLaunchdDevPlistPath, "LaunchDaemon plist path")
	clientPathFlag := fs.String("client-path", "", "agent-sudo binary path trusted for client checks")
	uidFlag := fs.String("uid", os.Getenv("SUDO_UID"), "target client uid")
	gidFlag := fs.String("gid", os.Getenv("SUDO_GID"), "target client gid")
	userFlag := fs.String("user", os.Getenv("SUDO_USER"), "target client username")
	jsonOut := fs.Bool("json", false, "json output for smoke result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("launchd-dev install must run as root")
	}
	uid, gid, userHome, err := resolveSmokeUser(*uidFlag, *gidFlag, *userFlag)
	if err != nil {
		return err
	}
	clientPath, err := launchdDevClientPath(*clientPathFlag)
	if err != nil {
		return err
	}
	plan, err := newLaunchdDevPlan(*root, *plistPath, gid)
	if err != nil {
		return err
	}
	result, installErr := installLaunchdDev(plan, uid, gid, userHome, clientPath, true)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		fmt.Fprintf(stdout, "agent-sudo launchd-dev %s\n", verb)
		fmt.Fprintf(stdout, "root: %s\n", plan.Root)
		fmt.Fprintf(stdout, "plist: %s\n", plan.PlistPath)
		fmt.Fprintf(stdout, "broker binary: %s\n", plan.BinaryPath)
		fmt.Fprintf(stdout, "trusted client: %s\n", clientPath)
		printLaunchdDevResult(stdout, result)
	}
	if installErr != nil {
		return installErr
	}
	return nil
}

func cmdLaunchdDevStatus(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("launchd-dev status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultLaunchdDevRoot, "disposable launchd-dev root")
	plistPath := fs.String("plist", defaultLaunchdDevPlistPath, "LaunchDaemon plist path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	plan, err := newLaunchdDevPlan(*root, *plistPath, os.Getgid())
	if err != nil {
		return err
	}
	loaded := "missing"
	if err := runLaunchctl(launchdDevPrintArgs(plan.Label)); err == nil {
		loaded = "loaded"
	}
	fmt.Fprintf(stdout, "label: %s (%s)\n", plan.Label, loaded)
	fmt.Fprintf(stdout, "root: %s (%s)\n", plan.Root, existsLabel(plan.Root))
	fmt.Fprintf(stdout, "plist: %s (%s)\n", plan.PlistPath, existsLabel(plan.PlistPath))
	fmt.Fprintf(stdout, "socket: %s (%s)\n", plan.Paths.SocketPath, existsLabel(plan.Paths.SocketPath))
	fmt.Fprintf(stdout, "audit: %s (%s)\n", plan.Paths.AuditPath, existsLabel(plan.Paths.AuditPath))
	return nil
}

func cmdLaunchdDevCheck(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("launchd-dev check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultLaunchdDevRoot, "disposable launchd-dev root")
	plistPath := fs.String("plist", defaultLaunchdDevPlistPath, "LaunchDaemon plist path")
	clientPathFlag := fs.String("client-path", "", "agent-sudo binary path trusted for client checks")
	uidFlag := fs.String("uid", os.Getenv("SUDO_UID"), "target client uid")
	gidFlag := fs.String("gid", os.Getenv("SUDO_GID"), "target client gid")
	userFlag := fs.String("user", os.Getenv("SUDO_USER"), "target client username")
	jsonOut := fs.Bool("json", false, "json output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("launchd-dev check must run as root")
	}
	uid, gid, userHome, err := resolveSmokeUser(*uidFlag, *gidFlag, *userFlag)
	if err != nil {
		return err
	}
	clientPath, err := launchdDevClientPath(*clientPathFlag)
	if err != nil {
		return err
	}
	plan, err := newLaunchdDevPlan(*root, *plistPath, gid)
	if err != nil {
		return err
	}
	result := runLaunchdDevCheck(plan, uid, gid, userHome, clientPath)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		printLaunchdDevResult(stdout, result)
	}
	if result.Status != "PASS" {
		return errors.New("launchd-dev check failed")
	}
	return nil
}

func cmdLaunchdDevUninstall(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("launchd-dev uninstall", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", defaultLaunchdDevRoot, "disposable launchd-dev root")
	plistPath := fs.String("plist", defaultLaunchdDevPlistPath, "LaunchDaemon plist path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("launchd-dev uninstall must run as root")
	}
	plan, err := newLaunchdDevPlan(*root, *plistPath, os.Getgid())
	if err != nil {
		return err
	}
	if err := uninstallLaunchdDev(plan); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "agent-sudo launchd-dev uninstalled\nroot removed: %s\nplist removed: %s\n", plan.Root, plan.PlistPath)
	return nil
}

func installLaunchdDev(plan launchdDevPlan, uid, gid int, userHome, clientPath string, cleanupOnFailure bool) (RootSmokeResult, error) {
	result := RootSmokeResult{Status: "FAIL", Root: plan.Root}
	fail := func(id string, err error) (RootSmokeResult, error) {
		result.Checks = append(result.Checks, RootSmokeCheck{ID: id, Status: "FAIL", Message: err.Error()})
		if cleanupOnFailure {
			_ = cleanupLaunchdDevBestEffort(plan)
			return result, fmt.Errorf("%s; cleaned up dev service", err)
		}
		return result, err
	}
	_ = stopLaunchdDev(plan)
	if err := ensureLaunchdDevPlistReplaceable(plan); err != nil {
		return fail("plist_replaceable", err)
	}
	if err := prepareLaunchdDev(plan, clientPath); err != nil {
		return fail("prepare", err)
	}
	if err := writeLaunchdDevPlist(plan); err != nil {
		return fail("write_plist", err)
	}
	if err := bootstrapLaunchdDev(plan); err != nil {
		return fail("bootstrap", err)
	}
	result = runLaunchdDevCheck(plan, uid, gid, userHome, clientPath)
	if result.Status != "PASS" {
		if cleanupOnFailure {
			_ = cleanupLaunchdDevBestEffort(plan)
			return result, errors.New("launchd-dev check failed; cleaned up dev service")
		}
		return result, errors.New("launchd-dev check failed")
	}
	return result, nil
}

func uninstallLaunchdDev(plan launchdDevPlan) error {
	_ = stopLaunchdDev(plan)
	if err := removeLaunchdDevPlist(plan); err != nil {
		return err
	}
	if err := safeRemoveLaunchdDev(plan.Root); err != nil {
		return err
	}
	return verifyLaunchdDevStopped(plan)
}

func newLaunchdDevPlan(root, plistPath string, gid int) (launchdDevPlan, error) {
	cleanRoot, err := cleanLaunchdDevPath(root)
	if err != nil {
		return launchdDevPlan{}, err
	}
	if plistPath == "" {
		return launchdDevPlan{}, errors.New("empty launchd-dev plist path")
	}
	cleanPlist, err := fsutil.Canonical(plistPath)
	if err != nil {
		return launchdDevPlan{}, err
	}
	allowedPlist := filepath.Clean(defaultLaunchdDevPlistPath)
	if cleanPlist != allowedPlist {
		return launchdDevPlan{}, fmt.Errorf("refusing launchd-dev plist path outside %s", allowedPlist)
	}
	paths := launchdDevPaths(cleanRoot)
	binaryPath := filepath.Join(cleanRoot, "bin", "agent-sudo")
	stdoutPath := filepath.Join(cleanRoot, "log", "broker.out")
	stderrPath := filepath.Join(cleanRoot, "log", "broker.err")
	plan := launchdDevPlan{
		Root:       cleanRoot,
		Paths:      paths,
		Label:      launchdDevLabel,
		PlistPath:  cleanPlist,
		BinaryPath: binaryPath,
		StdoutPath: stdoutPath,
		StderrPath: stderrPath,
		SocketGID:  gid,
	}
	plan.ProgramArguments = launchdDevBrokerArgs(binaryPath, gid)
	plan.Environment = launchdDevEnvironment(paths)
	return plan, nil
}

func launchdDevPaths(root string) config.Paths {
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

func launchdDevBrokerArgs(binaryPath string, gid int) []string {
	return []string{
		binaryPath,
		"broker",
		"serve",
		"--run-dir-mode", "0750",
		"--socket-mode", "0660",
		"--socket-uid", "0",
		"--socket-gid", strconv.Itoa(gid),
	}
}

func launchdDevEnvironment(paths config.Paths) map[string]string {
	return map[string]string{
		"AGENT_SUDO_RUN_DIR":      paths.RunDir,
		"AGENT_SUDO_SOCKET":       paths.SocketPath,
		"AGENT_SUDO_CONFIG_DIR":   paths.ConfigDir,
		"AGENT_SUDO_POLICY":       paths.PolicyPath,
		"AGENT_SUDO_TRUST":        paths.TrustPath,
		"AGENT_SUDO_STATE_DIR":    paths.StateDir,
		"AGENT_SUDO_AUDIT":        paths.AuditPath,
		"AGENT_SUDO_ARTIFACT_DIR": paths.ArtifactDir,
		"HOME":                    paths.Home,
		"PATH":                    "/usr/bin:/bin:/usr/sbin:/sbin",
		"TMPDIR":                  "/private/tmp",
	}
}

func launchdDevClientPath(path string) (string, error) {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		path = exe
	}
	return fsutil.CanonicalClient(path)
}

func prepareLaunchdDev(plan launchdDevPlan, clientPath string) error {
	if fsutil.PathExists(plan.Root) {
		if err := safeRemoveLaunchdDev(plan.Root); err != nil {
			return err
		}
	}
	if err := mkdirOwned(plan.Root, 0o755, 0, 0); err != nil {
		return err
	}
	markerPath := filepath.Join(plan.Root, launchdDevMarker)
	if err := os.WriteFile(markerPath, []byte("agent-sudo launchd dev disposable tree\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chown(markerPath, 0, 0); err != nil {
		return err
	}
	if err := mkdirOwned(filepath.Dir(plan.BinaryPath), 0o755, 0, 0); err != nil {
		return err
	}
	if err := copyRootOwnedFile(clientPath, plan.BinaryPath, 0o755); err != nil {
		return err
	}
	if err := mkdirOwned(plan.Paths.RunDir, 0o750, 0, plan.SocketGID); err != nil {
		return err
	}
	if err := mkdirOwned(plan.Paths.ConfigDir, 0o700, 0, 0); err != nil {
		return err
	}
	if err := mkdirOwned(plan.Paths.StateDir, 0o700, 0, 0); err != nil {
		return err
	}
	if err := mkdirOwned(filepath.Dir(plan.Paths.AuditPath), 0o700, 0, 0); err != nil {
		return err
	}
	if err := mkdirOwned(plan.Paths.ArtifactDir, 0o700, 0, 0); err != nil {
		return err
	}
	if err := mkdirOwned(filepath.Dir(plan.StdoutPath), 0o700, 0, 0); err != nil {
		return err
	}
	if err := writeLaunchdDevConfig(plan.Paths, clientPath, plan.BinaryPath); err != nil {
		return err
	}
	if _, _, err := createTamperedSmokeArtifact(plan.Paths); err != nil {
		return err
	}
	return mkdirOwned(plan.Root, 0o755, 0, 0)
}

func writeLaunchdDevConfig(paths config.Paths, clientPath, brokerBinaryPath string) error {
	if err := writeRootOwnedJSON(paths.PolicyPath, launchdDevPolicy(), 0o600); err != nil {
		return err
	}
	clients := []trust.Client{}
	for _, path := range uniqueNonEmpty([]string{clientPath, brokerBinaryPath}) {
		client, err := trust.ClientForPath(launchdDevClientID, path)
		if err != nil {
			return err
		}
		clients = append(clients, client)
	}
	return writeRootOwnedJSON(paths.TrustPath, trust.Store{Version: 1, Clients: clients}, 0o600)
}

func launchdDevPolicy() policy.Policy {
	return policy.Policy{
		Version: 1,
		Rules: []policy.PolicyRule{
			{
				ID:               "launchd-dev.id-u",
				Clients:          []string{launchdDevClientID},
				Executable:       "/usr/bin/id",
				Argv:             []policy.ArgMatcher{exactMatcher("-u")},
				Effect:           protocol.EffectReadOnly,
				Approval:         "not_required",
				TimeoutSeconds:   5,
				OutputLimitBytes: 1024,
			},
			{
				ID:               "launchd-dev.artifact.verified",
				Clients:          []string{launchdDevClientID},
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

func uniqueNonEmpty(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func copyRootOwnedFile(src, dst string, mode os.FileMode) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to copy symlink binary %s", src)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source binary %s is not a regular file", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".agent-sudo-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chown(tmpName, 0, 0); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chown(dst, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func renderLaunchdDevPlist(plan launchdDevPlan) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString("<dict>\n")
	writePlistString(&b, "Label", plan.Label)
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range plan.ProgramArguments {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", xmlEscape(arg))
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
	keys := make([]string, 0, len(plan.Environment))
	for key := range plan.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writePlistString(&b, key, plan.Environment[key])
	}
	b.WriteString("\t</dict>\n")
	writePlistString(&b, "WorkingDirectory", "/private/tmp")
	writePlistString(&b, "StandardOutPath", plan.StdoutPath)
	writePlistString(&b, "StandardErrorPath", plan.StderrPath)
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

func writePlistString(b *bytes.Buffer, key, value string) {
	fmt.Fprintf(b, "\t<key>%s</key>\n\t<string>%s</string>\n", xmlEscape(key), xmlEscape(value))
}

func xmlEscape(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

func writeLaunchdDevPlist(plan launchdDevPlan) error {
	if err := ensureLaunchdDevPlistReplaceable(plan); err != nil {
		return err
	}
	if err := os.WriteFile(plan.PlistPath, renderLaunchdDevPlist(plan), 0o644); err != nil {
		return err
	}
	if err := os.Chown(plan.PlistPath, 0, 0); err != nil {
		return err
	}
	return os.Chmod(plan.PlistPath, 0o644)
}

func ensureLaunchdDevPlistReplaceable(plan launchdDevPlan) error {
	if fsutil.PathExists(plan.PlistPath) {
		ok, err := launchdDevPlistLooksOwned(plan.PlistPath)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("refusing to replace non-dev plist %s", plan.PlistPath)
		}
	}
	return nil
}

func launchdDevPlistLooksOwned(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	text := string(b)
	return strings.Contains(text, launchdDevLabel) && strings.Contains(text, "agent-sudo-launchd-dev"), nil
}

func removeLaunchdDevPlist(plan launchdDevPlan) error {
	if !fsutil.PathExists(plan.PlistPath) {
		return nil
	}
	ok, err := launchdDevPlistLooksOwned(plan.PlistPath)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("refusing to remove non-dev plist %s", plan.PlistPath)
	}
	return os.Remove(plan.PlistPath)
}

func bootstrapLaunchdDev(plan launchdDevPlan) error {
	if err := runLaunchctl(launchdDevBootstrapArgs(plan.PlistPath)); err != nil {
		return err
	}
	if err := waitForLaunchdDevSocket(plan.Paths.SocketPath); err != nil {
		return err
	}
	return nil
}

func stopLaunchdDev(plan launchdDevPlan) error {
	first := runLaunchctl(launchdDevBootoutLabelArgs(plan.Label))
	second := runLaunchctl(launchdDevBootoutPlistArgs(plan.PlistPath))
	if first == nil || second == nil {
		_ = waitForPathGone(plan.Paths.SocketPath, 3*time.Second)
		return nil
	}
	return first
}

func runLaunchctl(args []string) error {
	_, err := runLaunchctlOutput(args)
	return err
}

func runLaunchctlOutput(args []string) (string, error) {
	cmd := exec.Command("/bin/launchctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return string(out), fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, msg)
		}
		return string(out), fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func launchdDevBootstrapArgs(plistPath string) []string {
	return []string{"bootstrap", "system", plistPath}
}

func launchdDevBootoutLabelArgs(label string) []string {
	return []string{"bootout", "system/" + label}
}

func launchdDevBootoutPlistArgs(plistPath string) []string {
	return []string{"bootout", "system", plistPath}
}

func launchdDevPrintArgs(label string) []string {
	return []string{"print", "system/" + label}
}

func waitForLaunchdDevSocket(socketPath string) error {
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if fsutil.PathExists(socketPath) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("launchd-dev broker socket did not appear at %s", socketPath)
}

func waitForPathGone(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !fsutil.PathExists(path) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("%s still exists", path)
}

func runLaunchdDevCheck(plan launchdDevPlan, uid, gid int, userHome, clientPath string) RootSmokeResult {
	result := RootSmokeResult{Status: "PASS", Root: plan.Root}
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

	if err := runLaunchctl(launchdDevPrintArgs(plan.Label)); err != nil {
		add("launchd_service", "FAIL", err.Error())
	} else {
		add("launchd_service", "PASS", "service loaded")
	}
	for _, check := range verifyLaunchdDevOwnership(plan, gid) {
		result.Checks = append(result.Checks, check)
		if check.Status == "FAIL" {
			result.Status = "FAIL"
		}
	}
	smokeClientPath := launchdDevCheckClientPath(plan, clientPath)
	add("smoke_client", "PASS", smokeClientPath)
	env := clientEnv(plan.Paths.SocketPath, userHome, launchdDevClientID)
	approved, err := runSmokeClientJSON(uid, gid, smokeClientPath, env, "request", "--json", "--client", launchdDevClientID, "--reason", "Read effective uid for broker project target launchd verification.", "--", "/usr/bin/id", "-u")
	if err != nil {
		addDecision("id_returns_root", "FAIL", responseMessageOrError(approved, err), approved.Decision)
	} else if approved.Decision != protocol.DecisionApproved || approved.ExitCode != 0 || strings.TrimSpace(approved.Stdout) != "0" {
		addDecision("id_returns_root", "FAIL", fmt.Sprintf("unexpected response stdout=%q exit=%d", approved.Stdout, approved.ExitCode), approved.Decision)
	} else {
		addDecision("id_returns_root", "PASS", "normal user client received root execution result", approved.Decision)
	}

	shellResp, _ := runSmokeClientJSON(uid, gid, smokeClientPath, env, "request", "--json", "--client", launchdDevClientID, "--reason", "Run shell command for broker project target launchd negative test.", "--", "/bin/sh", "-c", "id")
	if shellResp.Decision == protocol.DecisionApproved {
		addDecision("deny_shell", "FAIL", "shell command was approved", shellResp.Decision)
	} else {
		addDecision("deny_shell", "PASS", "shell command denied", shellResp.Decision)
	}

	relativeResp, _ := runSmokeClientJSON(uid, gid, smokeClientPath, env, "request", "--json", "--client", launchdDevClientID, "--reason", "Read effective uid for broker project target launchd negative test.", "--", "id", "-u")
	if relativeResp.Decision == protocol.DecisionApproved {
		addDecision("deny_relative_executable", "FAIL", "relative executable was approved", relativeResp.Decision)
	} else {
		addDecision("deny_relative_executable", "PASS", "relative executable denied", relativeResp.Decision)
	}

	envResp, _ := runSmokeClientJSON(uid, gid, smokeClientPath, append(env, "LD_PRELOAD=/private/tmp/agent-sudo-fake.dylib"), "request", "--json", "--client", launchdDevClientID, "--reason", "Read effective uid for broker project target launchd env negative test.", "--", "/usr/bin/id", "-u")
	if envResp.Decision == protocol.DecisionApproved {
		addDecision("deny_env_injection", "FAIL", "LD_PRELOAD request was approved", envResp.Decision)
	} else {
		addDecision("deny_env_injection", "PASS", "LD_PRELOAD request denied", envResp.Decision)
	}

	meta, object, err := createTamperedSmokeArtifact(plan.Paths)
	if err != nil {
		add("artifact_tamper_setup", "FAIL", err.Error())
	} else {
		artifactResp, _ := runSmokeClientJSON(uid, gid, smokeClientPath, env, "root-smoke", "client-artifact", "--client", launchdDevClientID, "--socket", plan.Paths.SocketPath, "--id", meta.ID, "--sha256", meta.SHA256, "--executable", object)
		if artifactResp.Decision != protocol.DecisionArtifactUnverified {
			addDecision("deny_artifact_tamper", "FAIL", "tampered artifact was not rejected", artifactResp.Decision)
		} else {
			addDecision("deny_artifact_tamper", "PASS", "tampered artifact rejected", artifactResp.Decision)
		}
	}

	checkAuditEvent(add, plan.Paths.AuditPath, "audit_approved_event", approved.RequestID, protocol.DecisionApproved)
	checkAuditEvent(add, plan.Paths.AuditPath, "audit_denied_event", shellResp.RequestID, shellResp.Decision)
	return result
}

func launchdDevCheckClientPath(plan launchdDevPlan, clientPath string) string {
	if fsutil.PathExists(plan.BinaryPath) {
		return plan.BinaryPath
	}
	return clientPath
}

func responseMessageOrError(resp protocol.BrokerResponse, err error) string {
	if resp.Message != "" {
		return resp.Message
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func collectLaunchdDevDiagnostics(plan launchdDevPlan, workspaceClientPath, checkClientPath string) LaunchdDevDiagnostics {
	serviceArgs := launchdDevPrintArgs(plan.Label)
	serviceOut, serviceErr := runLaunchctlOutput(serviceArgs)
	service := LaunchdDevCommandDiagnostic{
		Args:       append([]string{"/bin/launchctl"}, serviceArgs...),
		Success:    serviceErr == nil,
		OutputTail: lastLines(serviceOut, 40),
	}
	if serviceErr != nil {
		service.Error = serviceErr.Error()
	}
	diag := LaunchdDevDiagnostics{
		Label:               plan.Label,
		Root:                plan.Root,
		PlistPath:           plan.PlistPath,
		SocketPath:          plan.Paths.SocketPath,
		AuditPath:           plan.Paths.AuditPath,
		Service:             service,
		ExpectedCheckClient: inspectLaunchdDevBinary("expected_check_client", checkClientPath),
		Paths: []LaunchdDevPathDiagnostic{
			inspectLaunchdDevPath("root_dir", plan.Root, 0, -1, 0o755, true),
			inspectLaunchdDevPath("marker_file", filepath.Join(plan.Root, launchdDevMarker), 0, 0, 0o600, false),
			inspectLaunchdDevPath("bin_dir", filepath.Dir(plan.BinaryPath), 0, 0, 0o755, true),
			inspectLaunchdDevPath("broker_binary", plan.BinaryPath, 0, 0, 0o755, false),
			inspectLaunchdDevPath("plist_file", plan.PlistPath, 0, 0, 0o644, false),
			inspectLaunchdDevPath("run_dir", plan.Paths.RunDir, 0, plan.SocketGID, 0o750, true),
			inspectLaunchdDevPath("socket", plan.Paths.SocketPath, 0, plan.SocketGID, 0o660, false),
			inspectLaunchdDevPath("config_dir", plan.Paths.ConfigDir, 0, 0, 0o700, true),
			inspectLaunchdDevPath("policy_file", plan.Paths.PolicyPath, 0, 0, 0o600, false),
			inspectLaunchdDevPath("trust_file", plan.Paths.TrustPath, 0, 0, 0o600, false),
			inspectLaunchdDevPath("audit_dir", filepath.Dir(plan.Paths.AuditPath), 0, 0, 0o700, true),
			inspectLaunchdDevPath("audit_file", plan.Paths.AuditPath, 0, 0, 0o600, false),
			inspectLaunchdDevPath("artifact_dir", plan.Paths.ArtifactDir, 0, 0, 0o700, true),
			inspectLaunchdDevPath("log_dir", filepath.Dir(plan.StdoutPath), 0, 0, 0o700, true),
			inspectLaunchdDevPath("stdout_log", plan.StdoutPath, 0, 0, 0o600, false),
			inspectLaunchdDevPath("stderr_log", plan.StderrPath, 0, 0, 0o600, false),
		},
		Binaries: []LaunchdDevBinaryDiagnostic{
			inspectLaunchdDevBinary("dev_binary", plan.BinaryPath),
			inspectLaunchdDevBinary("workspace_binary", workspaceClientPath),
		},
		Audit: fileTail("audit", plan.Paths.AuditPath, 20),
		Logs: []LaunchdDevFileTail{
			fileTail("broker_stdout", plan.StdoutPath, 40),
			fileTail("broker_stderr", plan.StderrPath, 40),
		},
	}
	if store, err := trust.Load(plan.Paths.TrustPath); err != nil {
		diag.Trust = []LaunchdDevTrustDiagnostic{{Error: err.Error()}}
	} else {
		for _, entry := range store.Clients {
			diag.Trust = append(diag.Trust, inspectTrustEntry(entry))
		}
	}
	return diag
}

func inspectLaunchdDevPath(id, path string, wantUID, wantGID int, wantMode os.FileMode, wantDir bool) LaunchdDevPathDiagnostic {
	diag := LaunchdDevPathDiagnostic{
		ID:       id,
		Path:     path,
		WantMode: fmt.Sprintf("%#o", wantMode),
		WantUID:  wantUID,
		WantGID:  wantGID,
	}
	info, err := os.Lstat(path)
	if err != nil {
		diag.Error = err.Error()
		return diag
	}
	diag.Exists = true
	diag.IsDir = info.IsDir()
	diag.Mode = fmt.Sprintf("%#o", info.Mode().Perm())
	diag.Size = info.Size()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		diag.UID = int(st.Uid)
		diag.GID = int(st.Gid)
	}
	if !wantDir && info.Mode().IsRegular() {
		if hash, err := fsutil.SHA256File(path); err == nil {
			diag.SHA256 = hash
		} else {
			diag.Error = err.Error()
		}
	}
	return diag
}

func inspectTrustEntry(entry trust.Client) LaunchdDevTrustDiagnostic {
	diag := LaunchdDevTrustDiagnostic{
		ID:     entry.ID,
		Path:   entry.Path,
		SHA256: entry.SHA256,
	}
	hash, err := fsutil.SHA256File(entry.Path)
	if err != nil {
		diag.Error = err.Error()
		return diag
	}
	diag.Exists = true
	diag.ActualSHA256 = hash
	diag.MatchesFile = strings.EqualFold(hash, entry.SHA256)
	return diag
}

func inspectLaunchdDevBinary(id, path string) LaunchdDevBinaryDiagnostic {
	diag := LaunchdDevBinaryDiagnostic{ID: id, Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		diag.Error = err.Error()
		return diag
	}
	diag.Exists = true
	diag.Mode = fmt.Sprintf("%#o", info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		diag.UID = int(st.Uid)
		diag.GID = int(st.Gid)
	}
	hash, err := fsutil.SHA256File(path)
	if err != nil {
		diag.Error = err.Error()
		return diag
	}
	diag.SHA256 = hash
	return diag
}

func fileTail(id, path string, lines int) LaunchdDevFileTail {
	diag := LaunchdDevFileTail{ID: id, Path: path}
	if !fsutil.PathExists(path) {
		diag.Error = "missing"
		return diag
	}
	diag.Exists = true
	tail, err := audit.Tail(path, lines)
	if err != nil {
		diag.Error = err.Error()
		return diag
	}
	diag.Lines = tail
	return diag
}

func lastLines(text string, lines int) []string {
	if lines <= 0 {
		lines = 20
	}
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	all := strings.Split(text, "\n")
	if len(all) <= lines {
		return all
	}
	return all[len(all)-lines:]
}

func verifyLaunchdDevOwnership(plan launchdDevPlan, targetGID int) []RootSmokeCheck {
	checks := []RootSmokeCheck{}
	checks = append(checks, verifyPath("root_dir", plan.Root, 0, -1, 0o755, true))
	checks = append(checks, verifyPath("marker_file", filepath.Join(plan.Root, launchdDevMarker), 0, 0, 0o600, false))
	checks = append(checks, verifyPath("broker_binary", plan.BinaryPath, 0, 0, 0o755, false))
	checks = append(checks, verifyPath("plist_file", plan.PlistPath, 0, 0, 0o644, false))
	checks = append(checks, verifyPath("run_dir", plan.Paths.RunDir, 0, targetGID, 0o750, true))
	checks = append(checks, verifyPath("socket", plan.Paths.SocketPath, 0, targetGID, 0o660, false))
	checks = append(checks, verifyPath("config_dir", plan.Paths.ConfigDir, 0, 0, 0o700, true))
	checks = append(checks, verifyPath("policy_file", plan.Paths.PolicyPath, 0, 0, 0o600, false))
	checks = append(checks, verifyPath("trust_file", plan.Paths.TrustPath, 0, 0, 0o600, false))
	checks = append(checks, verifyPath("audit_dir", filepath.Dir(plan.Paths.AuditPath), 0, 0, 0o700, true))
	checks = append(checks, verifyPath("artifact_dir", plan.Paths.ArtifactDir, 0, 0, 0o700, true))
	return checks
}

func checkAuditEvent(add func(id, status, message string), auditPath, id, requestID, wantDecision string) {
	if requestID == "" {
		add(id, "FAIL", "missing request id")
		return
	}
	event, err := audit.Show(auditPath, requestID)
	if err != nil {
		add(id, "FAIL", err.Error())
		return
	}
	if event.Decision != wantDecision {
		add(id, "FAIL", fmt.Sprintf("audit decision=%s want=%s", event.Decision, wantDecision))
		return
	}
	add(id, "PASS", requestID)
}

func printLaunchdDevResult(w io.Writer, result RootSmokeResult) {
	printSmokeResult(w, "launchd-dev", result)
}

func printLaunchdDevDiagnostics(w io.Writer, diag LaunchdDevDiagnostics) {
	serviceStatus := "missing"
	if diag.Service.Success {
		serviceStatus = "loaded"
	}
	fmt.Fprintf(w, "launchd-dev diagnostics\n")
	fmt.Fprintf(w, "label: %s (%s)\n", diag.Label, serviceStatus)
	fmt.Fprintf(w, "root: %s\n", diag.Root)
	fmt.Fprintf(w, "plist: %s\n", diag.PlistPath)
	fmt.Fprintf(w, "socket: %s\n", diag.SocketPath)
	if diag.Service.Error != "" {
		fmt.Fprintf(w, "launchctl: %s\n", diag.Service.Error)
	}
	fmt.Fprintf(w, "expected_check_client: %s exists=%t sha256=%s\n", diag.ExpectedCheckClient.Path, diag.ExpectedCheckClient.Exists, diag.ExpectedCheckClient.SHA256)
	for _, path := range diag.Paths {
		line := fmt.Sprintf("%s path=%s exists=%t mode=%s uid=%d gid=%d", path.ID, path.Path, path.Exists, path.Mode, path.UID, path.GID)
		if path.SHA256 != "" {
			line += " sha256=" + path.SHA256
		}
		if path.Error != "" {
			line += " error=" + path.Error
		}
		fmt.Fprintln(w, line)
	}
	for _, trust := range diag.Trust {
		if trust.Error != "" && trust.Path == "" {
			fmt.Fprintf(w, "trust error=%s\n", trust.Error)
			continue
		}
		fmt.Fprintf(w, "trust id=%s path=%s sha256=%s exists=%t matches_file=%t", trust.ID, trust.Path, trust.SHA256, trust.Exists, trust.MatchesFile)
		if trust.ActualSHA256 != "" {
			fmt.Fprintf(w, " actual_sha256=%s", trust.ActualSHA256)
		}
		if trust.Error != "" {
			fmt.Fprintf(w, " error=%s", trust.Error)
		}
		fmt.Fprintln(w)
	}
	for _, binary := range diag.Binaries {
		fmt.Fprintf(w, "binary %s path=%s exists=%t sha256=%s mode=%s uid=%d gid=%d", binary.ID, binary.Path, binary.Exists, binary.SHA256, binary.Mode, binary.UID, binary.GID)
		if binary.Error != "" {
			fmt.Fprintf(w, " error=%s", binary.Error)
		}
		fmt.Fprintln(w)
	}
	printTail := func(t LaunchdDevFileTail) {
		fmt.Fprintf(w, "%s: %s exists=%t\n", t.ID, t.Path, t.Exists)
		if t.Error != "" {
			fmt.Fprintf(w, "%s_error: %s\n", t.ID, t.Error)
			return
		}
		for _, line := range t.Lines {
			fmt.Fprintf(w, "%s> %s\n", t.ID, line)
		}
	}
	printTail(diag.Audit)
	for _, log := range diag.Logs {
		printTail(log)
	}
	if len(diag.Service.OutputTail) > 0 {
		fmt.Fprintln(w, "launchctl_tail:")
		for _, line := range diag.Service.OutputTail {
			fmt.Fprintf(w, "launchctl> %s\n", line)
		}
	}
}

func printSmokeResult(w io.Writer, name string, result RootSmokeResult) {
	fmt.Fprintf(w, "agent-sudo %s: %s\nroot: %s\n", name, result.Status, result.Root)
	for _, check := range result.Checks {
		if check.Decision != "" {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", check.Status, check.ID, check.Decision, check.Message)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\n", check.Status, check.ID, check.Message)
		}
	}
}

func cleanLaunchdDevPath(root string) (string, error) {
	cleaned := filepath.Clean(root)
	if cleaned != defaultLaunchdDevRoot && !strings.HasPrefix(cleaned, defaultLaunchdDevRoot+"-") {
		return "", fmt.Errorf("refusing launchd-dev path outside %s*", defaultLaunchdDevRoot)
	}
	return cleaned, nil
}

func safeRemoveLaunchdDev(root string) error {
	cleaned, err := cleanLaunchdDevPath(root)
	if err != nil {
		return err
	}
	if !fsutil.PathExists(cleaned) {
		return nil
	}
	marker := filepath.Join(cleaned, launchdDevMarker)
	if !fsutil.PathExists(marker) {
		return fmt.Errorf("refusing to remove %s without %s marker; verify this is the disposable launchd-dev tree, then remove it manually with: sudo /bin/rm -rf %s", cleaned, launchdDevMarker, cleaned)
	}
	return os.RemoveAll(cleaned)
}

func verifyLaunchdDevStopped(plan launchdDevPlan) error {
	_ = waitForPathGone(plan.Paths.SocketPath, 2*time.Second)
	if fsutil.PathExists(plan.Paths.SocketPath) {
		return fmt.Errorf("launchd-dev socket still exists at %s", plan.Paths.SocketPath)
	}
	if err := runLaunchctl(launchdDevPrintArgs(plan.Label)); err == nil {
		return fmt.Errorf("launchd-dev service %s is still loaded", plan.Label)
	}
	running, details, err := launchdDevProcessRunning(plan.BinaryPath)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("launchd-dev broker process still running: %s", details)
	}
	return nil
}

func cleanupLaunchdDevBestEffort(plan launchdDevPlan) error {
	var problems []string
	if err := stopLaunchdDev(plan); err != nil {
		problems = append(problems, err.Error())
	}
	if err := removeLaunchdDevPlist(plan); err != nil {
		problems = append(problems, err.Error())
	}
	if err := safeRemoveLaunchdDev(plan.Root); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func launchdDevProcessRunning(binaryPath string) (bool, string, error) {
	cmd := exec.Command("/usr/bin/pgrep", "-fl", binaryPath)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil {
		return text != "", text, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 1 {
			return false, "", nil
		}
	}
	if text != "" {
		return false, "", fmt.Errorf("pgrep failed: %s", text)
	}
	return false, "", err
}
