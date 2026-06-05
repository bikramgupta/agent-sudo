package peer

import (
	"agent-sudo/internal/protocol"
	"fmt"
)

type Identity struct {
	UID        int
	GID        int
	PID        int
	Executable string
	SHA256     string
}

func ApplyObserved(req *protocol.BrokerRequest, peer Identity) *protocol.BrokerResponse {
	if peer.UID < 0 || peer.PID <= 0 || peer.Executable == "" || peer.SHA256 == "" {
		return protocol.Denial(req.RequestID, protocol.DecisionClientNotTrusted, "Broker could not derive complete peer identity from the Unix socket.", false)
	}
	if req.ClientExecutable != "" && req.ClientExecutable != peer.Executable {
		return protocol.Denial(req.RequestID, protocol.DecisionClientNotTrusted, fmt.Sprintf("Client executable metadata mismatch: request=%s observed=%s.", req.ClientExecutable, peer.Executable), false)
	}
	if req.ClientSHA256 != "" && req.ClientSHA256 != peer.SHA256 {
		return protocol.Denial(req.RequestID, protocol.DecisionClientNotTrusted, fmt.Sprintf("Client executable hash metadata mismatch: request=%s observed=%s.", req.ClientSHA256, peer.SHA256), false)
	}
	req.ClientExecutable = peer.Executable
	req.ClientSHA256 = peer.SHA256
	req.PeerObserved = true
	req.PeerUID = peer.UID
	req.PeerGID = peer.GID
	req.PeerPID = peer.PID
	return nil
}

func ObservedOrCurrentUID(req protocol.BrokerRequest) int {
	if req.PeerObserved {
		return req.PeerUID
	}
	return currentUID()
}

func ObservedOrCurrentPID(req protocol.BrokerRequest) int {
	if req.PeerObserved {
		return req.PeerPID
	}
	return currentPID()
}
