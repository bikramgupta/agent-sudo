package policy

import (
	"agent-sudo/internal/protocol"
	"os"
	"strings"
)

var dangerousEnvPrefixes = []string{
	"DYLD_",
	"LD_",
}

var dangerousEnvNames = map[string]bool{
	"LD_PRELOAD":               true,
	"DYLD_INSERT_LIBRARIES":    true,
	"BASH_ENV":                 true,
	"ENV":                      true,
	"IFS":                      true,
	"PYTHONPATH":               true,
	"PYTHONHOME":               true,
	"RUBYOPT":                  true,
	"PERL5LIB":                 true,
	"NODE_OPTIONS":             true,
	"NPM_CONFIG_PREFIX":        true,
	"HOMEBREW_BREW_GIT_REMOTE": true,
	"HOMEBREW_CORE_GIT_REMOTE": true,
}

func CollectEnvMetadata() map[string]string {
	out := map[string]string{}
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if key == "PATH" || key == "SHELL" || key == "HOME" || key == "TMPDIR" || isDangerousEnvKey(key) {
			out[key] = "[present]"
		}
	}
	return out
}

func isDangerousEnvKey(key string) bool {
	if dangerousEnvNames[key] {
		return true
	}
	for _, p := range dangerousEnvPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func DeniedEnv(req protocol.BrokerRequest, rule *PolicyRule) *protocol.BrokerResponse {
	allowed := map[string]bool{}
	for _, key := range rule.Env.Allow {
		allowed[key] = true
	}
	for key := range req.Env {
		if isDangerousEnvKey(key) && !allowed[key] {
			return protocol.Denial(req.RequestID, protocol.DecisionDenied, "Environment variable "+key+" is not allowed for brokered execution.", false)
		}
	}
	return nil
}

func SanitizedExecutionEnv(rule EnvPolicy) []string {
	allowed := map[string]bool{}
	for _, key := range rule.Allow {
		allowed[key] = true
	}
	if len(allowed) == 0 {
		return []string{}
	}
	out := []string{}
	for key := range allowed {
		if value, ok := os.LookupEnv(key); ok && !isDangerousEnvKey(key) {
			out = append(out, key+"="+value)
		}
	}
	return out
}
