// Command agent-sudo is the local privileged broker CLI. The production binary
// contains only the user-facing commands; build with -tags devtools to include
// the disposable root-smoke and launchd-dev harness used during development.
package main

import (
	"fmt"
	"os"

	"agent-sudo/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
