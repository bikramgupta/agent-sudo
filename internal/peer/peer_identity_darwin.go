//go:build darwin

package peer

/*
#cgo LDFLAGS: -lproc
#include <libproc.h>
#include <stdlib.h>
*/
import "C"

import (
	"agent-sudo/internal/fsutil"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	darwinSOLLocal      = 0
	darwinLocalPeerCred = 1
	darwinLocalPeerPID  = 2
)

type darwinXucred struct {
	Version uint32
	UID     uint32
	NGroups int16
	Groups  [16]uint32
}

func Observe(conn net.Conn) (Identity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return Identity{}, errors.New("connection is not a Unix domain socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return Identity{}, err
	}
	var peer Identity
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		uid, gid, pid, err := darwinPeerCredFromFD(fd)
		if err != nil {
			controlErr = err
			return
		}
		exe, err := darwinExecutablePathForPID(pid)
		if err != nil {
			controlErr = err
			return
		}
		hash, err := fsutil.SHA256File(exe)
		if err != nil {
			controlErr = err
			return
		}
		peer = Identity{UID: uid, GID: gid, PID: pid, Executable: exe, SHA256: hash}
	}); err != nil {
		return Identity{}, err
	}
	if controlErr != nil {
		return Identity{}, controlErr
	}
	return peer, nil
}

func darwinPeerCredFromFD(fd uintptr) (uid, gid, pid int, err error) {
	var cred darwinXucred
	credLen := uint32(unsafe.Sizeof(cred))
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(darwinSOLLocal),
		uintptr(darwinLocalPeerCred),
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&credLen)),
		0,
	); errno != 0 {
		return 0, 0, 0, errno
	}
	var pid32 int32
	pidLen := uint32(unsafe.Sizeof(pid32))
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd,
		uintptr(darwinSOLLocal),
		uintptr(darwinLocalPeerPID),
		uintptr(unsafe.Pointer(&pid32)),
		uintptr(unsafe.Pointer(&pidLen)),
		0,
	); errno != 0 {
		return 0, 0, 0, errno
	}
	gid = -1
	if cred.NGroups > 0 {
		gid = int(cred.Groups[0])
	}
	return int(cred.UID), gid, int(pid32), nil
}

func darwinExecutablePathForPID(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	buf := make([]byte, 4096)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint(len(buf)))
	if n <= 0 {
		return "", fmt.Errorf("proc_pidpath(%d) failed", pid)
	}
	path := string(buf[:int(n)])
	if resolved, err := fsutil.CanonicalClient(path); err == nil {
		return resolved, nil
	}
	return path, nil
}

func currentUID() int {
	return os.Getuid()
}

func currentPID() int {
	return os.Getpid()
}
