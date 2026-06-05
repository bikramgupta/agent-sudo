//go:build devtools

package main

import (
	"agent-sudo/internal/cli"
	"agent-sudo/internal/devtools"
)

// init wires the dev-only harness subcommands into the CLI dispatcher. This file
// is compiled only with -tags devtools, so the production binary never links the
// devtools package.
func init() {
	cli.RegisterCommand("root-smoke", devtools.CmdRootSmoke)
	cli.RegisterCommand("launchd-dev", devtools.CmdLaunchdDev)
}
