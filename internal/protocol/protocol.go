// Package protocol defines the request/response wire types and the shared
// decision and effect vocabulary exchanged between the agent-sudo CLI and the
// broker. It depends only on the standard library so every other package can
// import it without creating cycles.
package protocol

const (
	DecisionApproved           = "APPROVED"
	DecisionDenied             = "DENIED"
	DecisionReviewRequired     = "REVIEW_REQUIRED"
	DecisionReasonInvalid      = "REASON_INVALID"
	DecisionPolicyMismatch     = "POLICY_MISMATCH"
	DecisionClientNotTrusted   = "CLIENT_NOT_TRUSTED"
	DecisionSessionInvalid     = "SESSION_INVALID"
	DecisionArtifactUnverified = "ARTIFACT_UNVERIFIED"
	DecisionScopeTooBroad      = "SCOPE_TOO_BROAD"
)

const (
	EffectReadOnly              = "read_only"
	EffectValidateOnly          = "validate_only"
	EffectInstallOrUpdate       = "install_or_update"
	EffectServiceControl        = "service_control"
	EffectFileWrite             = "file_write"
	EffectPermissionChange      = "permission_change"
	EffectNetworkChange         = "network_change"
	EffectDiskOrPartitionChange = "disk_or_partition_change"
	EffectDestructive           = "destructive"
)

type BrokerRequest struct {
	SchemaVersion    int               `json:"schema_version"`
	Type             string            `json:"type"`
	RequestID        string            `json:"request_id"`
	ClientID         string            `json:"client_id"`
	ClientExecutable string            `json:"client_executable"`
	ClientSHA256     string            `json:"client_sha256"`
	PeerObserved     bool              `json:"-"`
	PeerUID          int               `json:"-"`
	PeerGID          int               `json:"-"`
	PeerPID          int               `json:"-"`
	CWD              string            `json:"cwd"`
	SessionID        string            `json:"session_id,omitempty"`
	Reason           string            `json:"reason"`
	Executable       string            `json:"executable"`
	Argv             []string          `json:"argv"`
	Env              map[string]string `json:"env,omitempty"`
	ArtifactID       string            `json:"artifact_id,omitempty"`
	ArtifactSHA256   string            `json:"artifact_sha256,omitempty"`
}

type BrokerResponse struct {
	RequestID            string   `json:"request_id"`
	Decision             string   `json:"decision"`
	Message              string   `json:"message"`
	Retryable            bool     `json:"retryable"`
	Missing              []string `json:"missing,omitempty"`
	SuggestedReasonShape string   `json:"suggested_reason_shape,omitempty"`
	PolicyID             string   `json:"policy_id,omitempty"`
	Effect               string   `json:"effect,omitempty"`
	ExitCode             int      `json:"exit_code,omitempty"`
	Stdout               string   `json:"stdout,omitempty"`
	Stderr               string   `json:"stderr,omitempty"`
	DurationMS           int64    `json:"duration_ms,omitempty"`
	ArtifactID           string   `json:"artifact_id,omitempty"`
	ArtifactSHA256       string   `json:"artifact_sha256,omitempty"`

	// Audit carries full-output capture statistics for the audit log. It is
	// never serialized to the client: the wire response carries the bounded
	// Stdout/Stderr, while the audit record needs the hash, length, and
	// truncation state of the complete (pre-truncation) output.
	Audit *AuditCapture `json:"-"`
}

// AuditCapture holds audit-only metadata derived from a command's full output
// and any artifact runtime-risk flags observed while evaluating the request.
type AuditCapture struct {
	StdoutSHA256    string
	StderrSHA256    string
	StdoutLen       int64
	StderrLen       int64
	StdoutTail      string
	StderrTail      string
	StdoutTruncated bool
	StderrTruncated bool
	RuntimeRisks    []string
}
