package broker

import (
	"fmt"
	"os"
	"path/filepath"

	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/protocol"
)

// FillClientMetadata populates the request with the calling binary's canonical
// executable path and SHA-256, the metadata the broker compares against the
// observed Unix peer and the trust store.
func FillClientMetadata(req *protocol.BrokerRequest) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = resolved
	}
	exe, err = fsutil.Canonical(exe)
	if err != nil {
		return err
	}
	hash, err := fsutil.SHA256File(exe)
	if err != nil {
		return err
	}
	req.ClientExecutable = exe
	req.ClientSHA256 = hash
	return nil
}

// ExitCodeError reports that a brokered command ran but exited non-zero. It lets
// the CLI surface the underlying exit code without treating it as a broker
// failure.
type ExitCodeError struct {
	Code int
}

func (e ExitCodeError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.Code)
}
