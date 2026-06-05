//go:build !darwin

package peer

import (
	"errors"
	"net"
	"os"
)

func Observe(conn net.Conn) (Identity, error) {
	return Identity{}, errors.New("Unix peer identity is not implemented on this platform")
}

func currentUID() int {
	return os.Getuid()
}

func currentPID() int {
	return os.Getpid()
}
