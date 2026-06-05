// Package devtools contains the disposable root-smoke and launchd-dev harness
// used to exercise the privileged broker during development. Every functional
// file is guarded by the "devtools" build tag, so this package is empty in
// production builds. Build with -tags devtools to include the harness and its
// root-smoke / launchd-dev subcommands.
package devtools
