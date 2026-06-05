package policy

import (
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/protocol"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Policy struct {
	Version int          `json:"version"`
	Rules   []PolicyRule `json:"rules"`
}

type PolicyRule struct {
	ID                    string         `json:"id"`
	Clients               []string       `json:"clients"`
	Executable            string         `json:"executable,omitempty"`
	Argv                  []ArgMatcher   `json:"argv"`
	Effect                string         `json:"effect"`
	Approval              string         `json:"approval"`
	CWD                   CWDPolicy      `json:"cwd,omitempty"`
	Env                   EnvPolicy      `json:"env,omitempty"`
	TimeoutSeconds        int            `json:"timeout_seconds,omitempty"`
	OutputLimitBytes      int            `json:"output_limit_bytes,omitempty"`
	AllowShell            bool           `json:"allow_shell,omitempty"`
	AllowShellMetachars   bool           `json:"allow_shell_metacharacters,omitempty"`
	AllowHighRiskWildcard bool           `json:"allow_high_risk_wildcard,omitempty"`
	Artifact              ArtifactPolicy `json:"artifact,omitempty"`
}

type CWDPolicy struct {
	Allow []string `json:"allow,omitempty"`
}

type EnvPolicy struct {
	Allow         []string `json:"allow,omitempty"`
	ClearPrefixes []string `json:"clear_prefixes,omitempty"`
}

type ArtifactPolicy struct {
	AllowVerified       bool `json:"allow_verified,omitempty"`
	AllowRuntimeNetwork bool `json:"allow_runtime_network,omitempty"`
	AllowInstallerHooks bool `json:"allow_installer_hooks,omitempty"`
}

type ArgMatcher struct {
	Exact  *string  `json:"exact,omitempty"`
	Enum   []string `json:"enum,omitempty"`
	Prefix *string  `json:"prefix,omitempty"`
	Any    bool     `json:"any,omitempty"`
}

func (m *ArgMatcher) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		m.Exact = &s
		return nil
	}
	type alias ArgMatcher
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*m = ArgMatcher(a)
	return nil
}

func (m ArgMatcher) Match(value string) bool {
	if m.Exact != nil {
		return value == *m.Exact
	}
	if len(m.Enum) > 0 {
		return slices.Contains(m.Enum, value)
	}
	if m.Prefix != nil {
		return strings.HasPrefix(value, *m.Prefix)
	}
	return m.Any
}

func LoadPolicy(path string) (Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Policy{Version: 1}, nil
		}
		return Policy{}, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return Policy{}, fmt.Errorf("policy files currently use JSON syntax in policy.yaml: %w", err)
	}
	if p.Version == 0 {
		p.Version = 1
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func SaveDefaultPolicy(path string) error {
	if fsutil.PathExists(path) {
		return nil
	}
	if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	p := DefaultPolicy()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func DefaultPolicy() Policy {
	hello := "hello"
	selfTest := "self-test-ok"
	return Policy{
		Version: 1,
		Rules: []PolicyRule{
			{
				ID:               "dev.echo.hello",
				Clients:          []string{"codex", "claude-code", "cursor", "opencode", "local-dev", "test-client"},
				Executable:       "/bin/echo",
				Argv:             []ArgMatcher{{Exact: &hello}},
				Effect:           protocol.EffectReadOnly,
				Approval:         "not_required",
				TimeoutSeconds:   10,
				OutputLimitBytes: 4096,
			},
			{
				ID:               "dev.echo.self_test",
				Clients:          []string{"codex", "claude-code", "cursor", "opencode", "local-dev", "test-client"},
				Executable:       "/bin/echo",
				Argv:             []ArgMatcher{{Exact: &selfTest}},
				Effect:           protocol.EffectReadOnly,
				Approval:         "not_required",
				TimeoutSeconds:   10,
				OutputLimitBytes: 4096,
			},
			{
				ID:               "artifact.verified.noargs",
				Clients:          []string{"codex", "claude-code", "cursor", "opencode", "local-dev", "test-client"},
				Argv:             []ArgMatcher{},
				Effect:           protocol.EffectReadOnly,
				Approval:         "not_required",
				Artifact:         ArtifactPolicy{AllowVerified: true},
				TimeoutSeconds:   30,
				OutputLimitBytes: 8192,
			},
		},
	}
}

func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if r.ID == "" {
			return errors.New("policy rule id is required")
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate policy id %q", r.ID)
		}
		seen[r.ID] = true
		if len(r.Clients) == 0 {
			return fmt.Errorf("policy %s has no clients", r.ID)
		}
		if !r.Artifact.AllowVerified {
			if !filepath.IsAbs(r.Executable) {
				return fmt.Errorf("policy %s executable must be absolute", r.ID)
			}
			if IsShellExecutable(r.Executable) && !r.AllowShell {
				return fmt.Errorf("policy %s shell executable requires allow_shell", r.ID)
			}
		}
		if r.Approval != "not_required" && r.Approval != "review_required" {
			return fmt.Errorf("policy %s has invalid approval %q", r.ID, r.Approval)
		}
		if !validEffect(r.Effect) {
			return fmt.Errorf("policy %s has invalid effect %q", r.ID, r.Effect)
		}
		for _, a := range r.Argv {
			if a.Any && !r.AllowHighRiskWildcard {
				return fmt.Errorf("policy %s contains broad argv wildcard without allow_high_risk_wildcard", r.ID)
			}
		}
	}
	return nil
}

func (p Policy) Match(req protocol.BrokerRequest, artifactVerified bool, runtimeRisks []string) (*PolicyRule, string) {
	for i := range p.Rules {
		r := &p.Rules[i]
		if !slices.Contains(r.Clients, req.ClientID) {
			continue
		}
		if req.ArtifactID != "" {
			if !r.Artifact.AllowVerified || !artifactVerified {
				continue
			}
			if RuntimeRiskBlocked(r.Artifact, runtimeRisks) {
				continue
			}
		} else if r.Executable != req.Executable {
			continue
		}
		if len(r.Argv) != len(req.Argv) {
			continue
		}
		matched := true
		for j, m := range r.Argv {
			if !m.Match(req.Argv[j]) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		if !cwdAllowed(r.CWD, req.CWD) {
			continue
		}
		return r, ""
	}
	return nil, protocol.DecisionReviewRequired
}

func cwdAllowed(policy CWDPolicy, cwd string) bool {
	if len(policy.Allow) == 0 {
		return true
	}
	cleanCWD, err := fsutil.Canonical(cwd)
	if err != nil {
		return false
	}
	for _, raw := range policy.Allow {
		expanded := os.ExpandEnv(raw)
		cleanAllow, err := fsutil.Canonical(expanded)
		if err != nil {
			continue
		}
		if cleanCWD == cleanAllow || strings.HasPrefix(cleanCWD, cleanAllow+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func validEffect(effect string) bool {
	switch effect {
	case protocol.EffectReadOnly, protocol.EffectValidateOnly, protocol.EffectInstallOrUpdate, protocol.EffectServiceControl,
		protocol.EffectFileWrite, protocol.EffectPermissionChange, protocol.EffectNetworkChange,
		protocol.EffectDiskOrPartitionChange, protocol.EffectDestructive:
		return true
	default:
		return false
	}
}

func RuntimeRiskBlocked(policy ArtifactPolicy, risks []string) bool {
	for _, r := range risks {
		if r == "network_at_runtime" && !policy.AllowRuntimeNetwork {
			return true
		}
		if r == "installer_with_hooks" && !policy.AllowInstallerHooks {
			return true
		}
	}
	return false
}

func InferEffect(executable string, argv []string) string {
	base := filepath.Base(executable)
	if IsShellExecutable(executable) {
		return protocol.EffectDestructive
	}
	if base == "visudo" && len(argv) >= 3 && argv[0] == "-c" && argv[1] == "-f" {
		return protocol.EffectValidateOnly
	}
	if base == "brew" && len(argv) >= 2 && argv[0] == "install" {
		return protocol.EffectInstallOrUpdate
	}
	if base == "launchctl" && len(argv) > 0 {
		return protocol.EffectServiceControl
	}
	if base == "diskutil" && slices.Contains(argv, "eraseDisk") {
		return protocol.EffectDestructive
	}
	if base == "rm" {
		return protocol.EffectDestructive
	}
	if (base == "chmod" || base == "chown") && slices.Contains(argv, "-R") {
		return protocol.EffectDestructive
	}
	return protocol.EffectReadOnly
}

func IsShellExecutable(path string) bool {
	switch filepath.Base(path) {
	case "sh", "bash", "zsh", "dash", "fish", "ksh":
		return true
	default:
		return false
	}
}

func HasShellMetacharacters(argv []string) (string, bool) {
	patterns := []string{"|", ">", "<", "$(", "`", "&&", "||", ";"}
	for _, arg := range argv {
		for _, p := range patterns {
			if strings.Contains(arg, p) {
				return p, true
			}
		}
	}
	return "", false
}

func ShellDenied(req protocol.BrokerRequest, rule *PolicyRule) *protocol.BrokerResponse {
	if IsShellExecutable(req.Executable) && !rule.AllowShell {
		return protocol.Denial(req.RequestID, protocol.DecisionScopeTooBroad, "Shell execution is denied unless an exact high-risk shell policy exists.", false)
	}
	if meta, ok := HasShellMetacharacters(req.Argv); ok && !rule.AllowShellMetachars {
		return protocol.Denial(req.RequestID, protocol.DecisionScopeTooBroad, fmt.Sprintf("Argument contains shell metacharacter %q and the matched policy does not allow shell-like syntax.", meta), false)
	}
	return nil
}
