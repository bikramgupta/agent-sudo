//go:build devtools

package devtools

import "agent-sudo/internal/fsutil"

func existsLabel(path string) string {
	if fsutil.PathExists(path) {
		return "present"
	}
	return "missing"
}
