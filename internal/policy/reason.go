package policy

import (
	"agent-sudo/internal/protocol"
	"strings"
	"unicode/utf8"
)

func ValidateReason(reason, effect, executable string, argv []string) *protocol.BrokerResponse {
	trimmed := strings.TrimSpace(reason)
	missing := []string{}
	if trimmed == "" {
		missing = append(missing, "task_context", "expected_outcome", "target_scope")
		return protocol.ReasonInvalid("", "Reason is required.", missing)
	}
	if utf8.RuneCountInString(trimmed) > 400 {
		return protocol.ReasonInvalid("", "Reason is too long; keep it under 400 characters.", []string{"concise_reason"})
	}
	lower := strings.ToLower(trimmed)
	generic := map[string]bool{
		"sudo": true, "need sudo": true, "needed": true, "fix issue": true,
		"sudo required": true, "install dependency": true, "run command": true,
		"please approve": true,
	}
	if generic[lower] || utf8.RuneCountInString(trimmed) < 18 {
		return protocol.ReasonInvalid("", "Reason does not explain why the command is needed for this task.", []string{"task_context", "expected_outcome"})
	}
	if !containsAny(lower, []string{"validate", "verify", "check", "test", "inspect", "install", "update", "run", "fetch", "import", "read", "show", "repair"}) {
		missing = append(missing, "expected_outcome")
	}
	if !containsAny(lower, []string{"target", "file", "package", "artifact", "socket", "policy", "audit", "project", "script", "path", "command", "broker"}) {
		missing = append(missing, "target_scope")
	}
	if effect == protocol.EffectInstallOrUpdate && containsAny(lower, []string{"validate", "verify", "check"}) && !containsAny(lower, []string{"install", "update", "package"}) {
		return protocol.ReasonInvalid("", "Reason describes validation but the command installs or updates software.", []string{"command_reason_consistency"})
	}
	if effect == protocol.EffectValidateOnly && containsAny(lower, []string{"install", "update", "delete", "remove", "erase"}) {
		return protocol.ReasonInvalid("", "Reason describes mutation but the command policy is validation-only.", []string{"command_reason_consistency"})
	}
	if len(missing) > 0 {
		return protocol.ReasonInvalid("", "Reason is missing audit context for this command.", missing)
	}
	return nil
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
