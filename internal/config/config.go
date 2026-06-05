// Package config resolves the on-disk locations agent-sudo uses for its run
// directory, socket, policy, trust store, audit log, and artifact store,
// honoring AGENT_SUDO_* environment overrides.
package config

import (
	"os"
	"path/filepath"
)

type Paths struct {
	Home        string
	RunDir      string
	SocketPath  string
	ConfigDir   string
	PolicyPath  string
	TrustPath   string
	StateDir    string
	AuditPath   string
	ArtifactDir string
}

func DefaultPaths() (Paths, error) {
	configDirEnv := os.Getenv("AGENT_SUDO_CONFIG_DIR")
	stateDirEnv := os.Getenv("AGENT_SUDO_STATE_DIR")
	runDirEnv := os.Getenv("AGENT_SUDO_RUN_DIR")

	home, err := os.UserHomeDir()
	if err != nil && (configDirEnv == "" || stateDirEnv == "" || runDirEnv == "") {
		return Paths{}, err
	}

	configDir := configDirEnv
	if configDir == "" {
		configDir = filepath.Join(home, ".config", "agent-sudo")
	}
	stateDir := stateDirEnv
	if stateDir == "" {
		stateDir = filepath.Join(home, ".local", "state", "agent-sudo")
	}
	runDir := runDirEnv
	if runDir == "" {
		runDir = filepath.Join(home, ".agent-sudo", "run")
	}

	p := Paths{
		Home:        home,
		RunDir:      runDir,
		SocketPath:  EnvOrDefault("AGENT_SUDO_SOCKET", filepath.Join(runDir, "broker.sock")),
		ConfigDir:   configDir,
		PolicyPath:  EnvOrDefault("AGENT_SUDO_POLICY", filepath.Join(configDir, "policy.yaml")),
		TrustPath:   EnvOrDefault("AGENT_SUDO_TRUST", filepath.Join(configDir, "trust.json")),
		StateDir:    stateDir,
		AuditPath:   EnvOrDefault("AGENT_SUDO_AUDIT", filepath.Join(stateDir, "audit.jsonl")),
		ArtifactDir: EnvOrDefault("AGENT_SUDO_ARTIFACT_DIR", filepath.Join(stateDir, "artifacts")),
	}
	return p, nil
}

// EnvOrDefault returns the value of the named environment variable, or fallback
// when it is unset or empty.
func EnvOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
