package mcpproxy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"sync/atomic"
)

// JSON-RPC error codes
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInvalidParams  = -32602
	codeMethodNotFound = -32601
	codeInternalError  = -32603
)

// message is any JSON-RPC message. Requests have a method and an id,
// notifications have a method and no id, and responses have no method.
type message struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Method  string         `json:"method,omitempty"`
	Params  jsontext.Value `json:"params,omitzero"`
	Result  jsontext.Value `json:"result,omitzero"`
	Error   *rpcError      `json:"error,omitempty"`
}

type rpcError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    jsontext.Value `json:"data,omitzero"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

func (m *message) isRequest() bool {
	return m.Method != "" && m.ID != nil
}

func (m *message) isNotification() bool {
	return m.Method != "" && m.ID == nil
}

// idKey identifies a request by its id.
func (m *message) idKey() string {
	return string(m.ID)
}

func newRequest(method string, params any) (*message, error) {
	msg := &message{JSONRPC: "2.0", ID: nextId(), Method: method}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		msg.Params = raw
	}
	return msg, nil
}

func newNotification(method string) *message {
	return &message{JSONRPC: "2.0", Method: method}
}

func newResult(id jsontext.Value, result any) *message {
	raw, err := json.Marshal(result)
	if err != nil {
		return newError(id, codeInternalError, err.Error())
	}
	return &message{JSONRPC: "2.0", ID: id, Result: raw}
}

func newError(id jsontext.Value, code int, text string) *message {
	if id == nil {
		id = jsontext.Value("null")
	}
	return &message{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: text}}
}

// newToolError reports a failed tool call in a way the model can see.
func newToolError(id jsontext.Value, text string) *message {
	return newResult(id, map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}},
		"isError": true,
	})
}

var lastId atomic.Int64

// nextId returns an id for requests the proxy makes itself, which won't clash
// with the client's.
func nextId() jsontext.Value {
	raw, _ := json.Marshal(fmt.Sprintf("aws-sso-mcp-proxy-%d", lastId.Add(1)))
	return raw
}
