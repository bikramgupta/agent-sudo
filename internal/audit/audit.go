// Package audit defines the append-only audit record schema, a crash-safe JSONL
// logger, and the bounded output capture used to record command results without
// storing unbounded output or secrets.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"agent-sudo/internal/fsutil"
)

type Event struct {
	SchemaVersion     int        `json:"schema_version"`
	TS                time.Time  `json:"ts"`
	Sequence          uint64     `json:"sequence"`
	RequestID         string     `json:"request_id"`
	ClientID          string     `json:"client_id,omitempty"`
	UID               int        `json:"uid"`
	PeerPID           int        `json:"peer_pid,omitempty"`
	ClientExecutable  string     `json:"client_executable,omitempty"`
	CWD               string     `json:"cwd,omitempty"`
	SessionID         string     `json:"session_id,omitempty"`
	Reason            string     `json:"reason,omitempty"`
	ArtifactID        string     `json:"artifact_id,omitempty"`
	ArtifactSHA256    string     `json:"artifact_sha256,omitempty"`
	Executable        string     `json:"executable,omitempty"`
	Argv              []string   `json:"argv,omitempty"`
	Decision          string     `json:"decision"`
	PolicyID          string     `json:"policy_id,omitempty"`
	Effect            string     `json:"effect,omitempty"`
	Approval          string     `json:"approval,omitempty"`
	ApprovalExpiresAt *time.Time `json:"approval_expires_at,omitempty"`
	ExitCode          *int       `json:"exit_code,omitempty"`
	Timeout           bool       `json:"timeout"`
	DurationMS        int64      `json:"duration_ms,omitempty"`
	StdoutSHA256      string     `json:"stdout_sha256,omitempty"`
	StderrSHA256      string     `json:"stderr_sha256,omitempty"`
	StdoutLen         int64      `json:"stdout_len,omitempty"`
	StderrLen         int64      `json:"stderr_len,omitempty"`
	StdoutTail        string     `json:"stdout_tail,omitempty"`
	StderrTail        string     `json:"stderr_tail,omitempty"`
	StdoutTruncated   bool       `json:"stdout_truncated,omitempty"`
	StderrTruncated   bool       `json:"stderr_truncated,omitempty"`
	Message           string     `json:"message,omitempty"`
	Retryable         bool       `json:"retryable,omitempty"`
	Missing           []string   `json:"missing,omitempty"`
	RuntimeRiskFlags  []string   `json:"runtime_risk_flags,omitempty"`
}

type Logger struct {
	path string
	mu   sync.Mutex
	seq  uint64
}

func NewLogger(path string) *Logger {
	return &Logger{path: path}
}

func (l *Logger) Append(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := fsutil.EnsurePrivateDir(filepathDir(l.path)); err != nil {
		return err
	}
	l.seq++
	event.Sequence = l.seq
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func Tail(path string, lines int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if lines <= 0 {
		lines = 20
	}
	ring := make([]string, 0, lines)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if len(ring) == lines {
			copy(ring, ring[1:])
			ring[lines-1] = scanner.Text()
		} else {
			ring = append(ring, scanner.Text())
		}
	}
	return ring, scanner.Err()
}

func Show(path, requestID string) (*Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		if event.RequestID == requestID {
			return &event, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("request id %s not found", requestID)
}

// Capture is an io.Writer that records a bounded prefix of output for return to
// the client while tracking the full length, SHA-256, and truncation state for
// the audit record.
type Capture struct {
	limit     int
	buf       []byte
	total     int64
	truncated bool
	hasher    hash.Hash
}

func NewCapture(limit int) *Capture {
	if limit <= 0 {
		limit = 32768
	}
	return &Capture{limit: limit, hasher: sha256.New()}
}

func (b *Capture) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	_, _ = b.hasher.Write(p)
	remaining := b.limit - len(b.buf)
	if remaining > 0 {
		if len(p) <= remaining {
			b.buf = append(b.buf, p...)
		} else {
			b.buf = append(b.buf, p[:remaining]...)
			b.truncated = true
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *Capture) String() string {
	return string(b.buf)
}

func (b *Capture) SHA256() string {
	if b.total == 0 {
		return ""
	}
	return hex.EncodeToString(b.hasher.Sum(nil))
}

func (b *Capture) Tail(max int) string {
	if max <= 0 {
		max = 512
	}
	s := string(b.buf)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return RedactSecrets(s)
}

func (b *Capture) Len() int64 {
	return b.total
}

func (b *Capture) Truncated() bool {
	return b.truncated
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password)=([^\s]+)`),
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{12,}`),
}

// RedactSecrets masks common secret patterns in captured output before it is
// written to the audit log.
func RedactSecrets(s string) string {
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
			if strings.HasPrefix(strings.ToLower(match), "sk-") {
				return "sk-[redacted]"
			}
			parts := strings.SplitN(match, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=[redacted]"
			}
			return "[redacted]"
		})
	}
	return out
}

func filepathDir(path string) string {
	i := strings.LastIndex(path, string(os.PathSeparator))
	if i <= 0 {
		return "."
	}
	return path[:i]
}
