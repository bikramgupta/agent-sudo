package trust

import (
	"agent-sudo/internal/fsutil"
	"agent-sudo/internal/protocol"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	Version int      `json:"version"`
	Clients []Client `json:"clients"`
}

type Client struct {
	ID      string    `json:"id"`
	Path    string    `json:"path"`
	SHA256  string    `json:"sha256"`
	AddedAt time.Time `json:"added_at"`
}

func Load(path string) (Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Store{Version: 1}, nil
		}
		return Store{}, err
	}
	var store Store
	if err := json.Unmarshal(b, &store); err != nil {
		return Store{}, err
	}
	if store.Version == 0 {
		store.Version = 1
	}
	return store, nil
}

func Save(path string, store Store) error {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func AddClient(path, id, clientPath string) (Client, error) {
	if id == "" {
		return Client{}, fmt.Errorf("client id is required")
	}
	client, err := ClientForPath(id, clientPath)
	if err != nil {
		return Client{}, err
	}
	store, err := Load(path)
	if err != nil {
		return Client{}, err
	}
	replaced := false
	for i := range store.Clients {
		if store.Clients[i].ID == id {
			store.Clients[i] = client
			replaced = true
			break
		}
	}
	if !replaced {
		store.Clients = append(store.Clients, client)
	}
	return client, Save(path, store)
}

func ClientForPath(id, clientPath string) (Client, error) {
	canon, err := fsutil.CanonicalClient(clientPath)
	if err != nil {
		return Client{}, err
	}
	hash, err := fsutil.SHA256File(canon)
	if err != nil {
		return Client{}, err
	}
	return Client{
		ID:      id,
		Path:    canon,
		SHA256:  hash,
		AddedAt: time.Now(),
	}, nil
}

func (s Store) Match(req protocol.BrokerRequest) bool {
	if req.ClientID == "" || req.ClientExecutable == "" || req.ClientSHA256 == "" {
		return false
	}
	reqPath, err := fsutil.Canonical(req.ClientExecutable)
	if err != nil {
		return false
	}
	for _, c := range s.Clients {
		trustedPath := c.Path
		if canon, err := fsutil.CanonicalClient(c.Path); err == nil {
			trustedPath = canon
		}
		if c.ID == req.ClientID && trustedPath == reqPath && strings.EqualFold(c.SHA256, req.ClientSHA256) {
			return true
		}
	}
	return false
}

func (s Store) MismatchMessage(req protocol.BrokerRequest) string {
	parts := []string{
		fmt.Sprintf("client_id=%s", req.ClientID),
		fmt.Sprintf("observed_path=%s", req.ClientExecutable),
		fmt.Sprintf("observed_sha256=%s", req.ClientSHA256),
	}
	matches := []string{}
	for _, c := range s.Clients {
		if c.ID != req.ClientID {
			continue
		}
		trustedPath := c.Path
		if canon, err := fsutil.CanonicalClient(c.Path); err == nil {
			trustedPath = canon
		}
		matches = append(matches, fmt.Sprintf("{path=%s sha256=%s}", trustedPath, c.SHA256))
	}
	if len(matches) == 0 {
		parts = append(parts, "trusted_entries=[]")
	} else {
		parts = append(parts, "trusted_entries=["+strings.Join(matches, ", ")+"]")
	}
	return "Client is not enrolled or executable metadata changed: " + strings.Join(parts, " ")
}
