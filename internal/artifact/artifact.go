package artifact

import (
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/protocol"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type Store struct {
	root string
}

type Metadata struct {
	ID            string    `json:"id"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	SourceType    string    `json:"source_type"`
	RequestedPath string    `json:"requested_path,omitempty"`
	ResolvedPath  string    `json:"resolved_path,omitempty"`
	URL           string    `json:"url,omitempty"`
	ImportedAt    time.Time `json:"imported_at"`
	RiskFlags     []string  `json:"risk_flags,omitempty"`
}

func NewStore(root string) Store {
	return Store{root: root}
}

func (s Store) ensure() error {
	if err := fsutil.EnsurePrivateDir(s.root); err != nil {
		return err
	}
	if err := fsutil.EnsurePrivateDir(filepath.Join(s.root, "objects")); err != nil {
		return err
	}
	return fsutil.EnsurePrivateDir(filepath.Join(s.root, "metadata"))
}

func (s Store) ObjectPath(hash string) string {
	return filepath.Join(s.root, "objects", hash)
}

func (s Store) metadataPath(id string) string {
	return filepath.Join(s.root, "metadata", id+".json")
}

func artifactID(hash string) string {
	if len(hash) < 16 {
		return "art_" + hash
	}
	return "art_" + hash[:16]
}

func (s Store) Import(path string) (Metadata, error) {
	if err := s.ensure(); err != nil {
		return Metadata{}, err
	}
	requested, err := fsutil.Canonical(path)
	if err != nil {
		return Metadata{}, err
	}
	resolved, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return Metadata{}, err
	}
	if err := rejectUnsafeSourcePath(requested, resolved); err != nil {
		return Metadata{}, err
	}
	content, err := os.ReadFile(resolved)
	if err != nil {
		return Metadata{}, err
	}
	return s.StoreContent(content, Metadata{
		SourceType:    "local_import",
		RequestedPath: requested,
		ResolvedPath:  resolved,
		ImportedAt:    time.Now(),
		RiskFlags:     scanArtifactRisks(content),
	})
}

func (s Store) Fetch(ctx context.Context, rawURL, expectedSHA string, client *http.Client, maxBytes int64) (Metadata, error) {
	if err := s.ensure(); err != nil {
		return Metadata{}, err
	}
	if expectedSHA == "" {
		return Metadata{}, Error{Decision: protocol.DecisionArtifactUnverified, Message: "fetch requires a pinned sha256"}
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Metadata{}, err
	}
	if parsed.Scheme != "https" {
		return Metadata{}, Error{Decision: protocol.DecisionDenied, Message: "fetch requires HTTPS"}
	}
	if client == nil {
		client = http.DefaultClient
	}
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Metadata{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Metadata{}, fmt.Errorf("fetch failed with HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return Metadata{}, err
	}
	if int64(len(content)) > maxBytes {
		return Metadata{}, Error{Decision: protocol.DecisionScopeTooBroad, Message: "artifact exceeds size limit"}
	}
	hash := fsutil.SHA256Bytes(content)
	if !strings.EqualFold(hash, expectedSHA) {
		return Metadata{}, Error{Decision: protocol.DecisionArtifactUnverified, Message: "sha256 mismatch"}
	}
	return s.StoreContent(content, Metadata{
		SourceType: "fetch",
		URL:        rawURL,
		ImportedAt: time.Now(),
		RiskFlags:  scanArtifactRisks(content),
	})
}

func (s Store) StoreContent(content []byte, meta Metadata) (Metadata, error) {
	if err := s.ensure(); err != nil {
		return Metadata{}, err
	}
	hash := fsutil.SHA256Bytes(content)
	meta.SHA256 = hash
	meta.ID = artifactID(hash)
	meta.Size = int64(len(content))
	objectPath := s.ObjectPath(hash)
	if !fsutil.PathExists(objectPath) {
		tmp, err := os.CreateTemp(filepath.Dir(objectPath), ".tmp-*")
		if err != nil {
			return Metadata{}, err
		}
		tmpName := tmp.Name()
		if _, err := io.Copy(tmp, bytes.NewReader(content)); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return Metadata{}, err
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpName)
			return Metadata{}, err
		}
		if err := os.Chmod(tmpName, 0o500); err != nil {
			os.Remove(tmpName)
			return Metadata{}, err
		}
		if err := os.Rename(tmpName, objectPath); err != nil {
			os.Remove(tmpName)
			return Metadata{}, err
		}
	}
	if err := s.writeMetadata(meta); err != nil {
		return Metadata{}, err
	}
	return meta, nil
}

func (s Store) writeMetadata(meta Metadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.metadataPath(meta.ID), append(b, '\n'), 0o600)
}

func (s Store) Load(id string) (Metadata, error) {
	if err := s.ensure(); err != nil {
		return Metadata{}, err
	}
	b, err := os.ReadFile(s.metadataPath(id))
	if err != nil {
		return Metadata{}, err
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Metadata{}, err
	}
	return meta, nil
}

func (s Store) Verify(id string) (Metadata, string, error) {
	meta, err := s.Load(id)
	if err != nil {
		return Metadata{}, "", err
	}
	object := s.ObjectPath(meta.SHA256)
	info, err := os.Lstat(object)
	if err != nil {
		return Metadata{}, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Metadata{}, "", Error{Decision: protocol.DecisionArtifactUnverified, Message: "stored artifact is a symlink"}
	}
	if !info.Mode().IsRegular() {
		return Metadata{}, "", Error{Decision: protocol.DecisionArtifactUnverified, Message: "stored artifact is not a regular file"}
	}
	hash, err := fsutil.SHA256File(object)
	if err != nil {
		return Metadata{}, "", err
	}
	if !strings.EqualFold(hash, meta.SHA256) {
		return Metadata{}, "", Error{Decision: protocol.DecisionArtifactUnverified, Message: "stored artifact hash changed"}
	}
	return meta, object, nil
}

func rejectUnsafeSourcePath(requested, resolved string) error {
	info, err := os.Lstat(requested)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Error{Decision: protocol.DecisionDenied, Message: "artifact import rejects symlink paths"}
	}
	if !info.Mode().IsRegular() {
		return Error{Decision: protocol.DecisionDenied, Message: "artifact import requires a regular file"}
	}
	if runtime.GOOS != "windows" {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			return Error{Decision: protocol.DecisionDenied, Message: "artifact import rejects hardlinked files"}
		}
	}
	dir := filepath.Dir(resolved)
	for {
		dinfo, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if dinfo.Mode()&os.ModeSymlink != 0 {
			return Error{Decision: protocol.DecisionDenied, Message: "artifact import rejects symlink parent paths"}
		}
		// A group/world-writable directory is unsafe because another process
		// could swap the file. The sticky bit removes that risk (only the
		// owner can rename/delete entries), so sticky dirs such as /tmp are
		// accepted, matching standard safe-path semantics.
		if fsutil.IsUnsafeMode(dinfo.Mode()) && dinfo.Mode()&os.ModeSticky == 0 {
			return Error{Decision: protocol.DecisionDenied, Message: "artifact import rejects group/world-writable parent directories"}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func scanArtifactRisks(content []byte) []string {
	lower := strings.ToLower(string(content))
	risks := []string{}
	if strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ") ||
		strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		risks = append(risks, "network_at_runtime")
	}
	if strings.Contains(lower, "brew install") || strings.Contains(lower, "npm install") ||
		strings.Contains(lower, "pip install") || strings.Contains(lower, "cargo install") {
		risks = append(risks, "installer_with_hooks")
	}
	return risks
}

type Error struct {
	Decision string
	Message  string
}

func (e Error) Error() string {
	return e.Message
}
