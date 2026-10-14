package mcpproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gordonmleigh/aws-sso/agent"
)

// handshakeVersion is the version of the cache format. A cache from another
// version is ignored.
const handshakeVersion = 2

// handshake is what the upstream server said when we connected, and its lists
// of tools, prompts and resources, cached so that the client can be answered
// without connecting (and so without credentials). It holds nothing secret.
type handshake struct {
	Version         int            `json:"version"`
	Endpoint        string         `json:"endpoint"`
	FetchedAt       time.Time      `json:"fetchedAt"`
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    jsontext.Value `json:"capabilities,omitzero"`
	ServerInfo      jsontext.Value `json:"serverInfo,omitzero"`
	Instructions    string         `json:"instructions,omitempty"`
	// Lists maps each list method the server supports to everything it
	// returned.
	Lists map[string][]jsontext.Value `json:"lists"`
}

// listMethod is a list request that's answered from the cache.
type listMethod struct {
	method string
	// capability is what the server must advertise for it to be supported
	capability string
	// field is the name of the list in the result
	field string
	// changed is the notification for when the list changes
	changed string
}

var listMethods = []listMethod{
	{"tools/list", "tools", "tools", "notifications/tools/list_changed"},
	{"prompts/list", "prompts", "prompts", "notifications/prompts/list_changed"},
	{"resources/list", "resources", "resources", "notifications/resources/list_changed"},
	{
		"resources/templates/list",
		"resources",
		"resourceTemplates",
		"notifications/resources/list_changed",
	},
}

// findListMethod returns the list method for a request method, or nil.
func findListMethod(method string) *listMethod {
	for i := range listMethods {
		if listMethods[i].method == method {
			return &listMethods[i]
		}
	}
	return nil
}

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    jsontext.Value `json:"capabilities,omitzero"`
	ServerInfo      jsontext.Value `json:"serverInfo,omitzero"`
	Instructions    string         `json:"instructions,omitempty"`
}

// hasCapability reports whether the server advertises a capability.
func (init *initializeResult) hasCapability(name string) bool {
	var caps map[string]jsontext.Value
	return json.Unmarshal(init.Capabilities, &caps) == nil && caps[name] != nil
}

func newHandshake(
	endpoint string,
	init *initializeResult,
	lists map[string][]jsontext.Value,
) *handshake {
	return &handshake{
		Version:         handshakeVersion,
		Endpoint:        endpoint,
		FetchedAt:       time.Now(),
		ProtocolVersion: init.ProtocolVersion,
		Capabilities:    init.Capabilities,
		ServerInfo:      init.ServerInfo,
		Instructions:    init.Instructions,
		Lists:           lists,
	}
}

// sameAs reports whether h and other would look the same to the client.
func (h *handshake) sameAs(other *handshake) bool {
	if h.ProtocolVersion != other.ProtocolVersion ||
		h.Instructions != other.Instructions ||
		!sameJson(h.Capabilities, other.Capabilities) ||
		!sameJson(h.ServerInfo, other.ServerInfo) {
		return false
	}
	for _, lm := range listMethods {
		if !h.sameList(other, lm.method) {
			return false
		}
	}
	return true
}

func (h *handshake) sameList(other *handshake, method string) bool {
	a, b := h.Lists[method], other.Lists[method]
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameJson(a[i], b[i]) {
			return false
		}
	}
	return true
}

// listChanged reports whether the server says it notifies about changes to a
// capability's lists.
func (h *handshake) listChanged(capability string) bool {
	var caps map[string]struct {
		ListChanged bool `json:"listChanged"`
	}
	return json.Unmarshal(h.Capabilities, &caps) == nil && caps[capability].ListChanged
}

func sameJson(a jsontext.Value, b jsontext.Value) bool {
	a, b = bytes.Clone(a), bytes.Clone(b)
	// anything that isn't valid JSON is just compared as it is
	_ = a.Canonicalize()
	_ = b.Canonicalize()
	return bytes.Equal(a, b)
}

func defaultCachePath(endpoint string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(endpoint))
	name := hex.EncodeToString(hash[:])[:16] + ".json"
	return filepath.Join(dir, agent.Label, "mcp", name), nil
}

// loadHandshake returns nil if there's no usable cache for endpoint.
func loadHandshake(path string, endpoint string) (*handshake, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var h handshake
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	if h.Version != handshakeVersion || h.Endpoint != endpoint {
		return nil, nil
	}
	return &h, nil
}

func saveHandshake(path string, h *handshake) error {
	data, err := json.Marshal(h, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// CreateTemp makes the file 0600
	tmp, err := os.CreateTemp(dir, ".handshake-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
