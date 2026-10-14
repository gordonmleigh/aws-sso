package mcpproxy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestReadEvents(t *testing.T) {
	stream := ": comment\r\n" +
		"event: message\r\n" +
		"data: {\"a\":\r\n" +
		"data: 1}\r\n" +
		"\r\n" +
		"id: 2\n" +
		"data:{\"b\":2}\n" +
		"\n" +
		"retry: 10\n" +
		"\n" +
		"data: last"

	var got []string
	err := readEvents(strings.NewReader(stream), func(data []byte) error {
		got = append(got, string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"{\"a\":\n1}", "{\"b\":2}", "last"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}

	got = nil
	err = readEvents(strings.NewReader(stream), func(data []byte) error {
		got = append(got, string(data))
		return errStopEvents
	})
	if err != nil || len(got) != 1 {
		t.Errorf("stopping: got %q, %v", got, err)
	}

	failure := errors.New("failure")
	err = readEvents(strings.NewReader(stream), func(data []byte) error { return failure })
	if !errors.Is(err, failure) {
		t.Errorf("got error %v, want %v", err, failure)
	}
}

func TestInjectMeta(t *testing.T) {
	meta := map[string]string{"AWS_REGION": "eu-west-1", "OTHER": "x"}

	got, err := injectMeta(
		jsontext.Value(`{"name":"t","_meta":{"OTHER":"keep","progressToken":1}}`),
		meta,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertJson(
		t,
		got,
		`{"name":"t","_meta":{"AWS_REGION":"eu-west-1","OTHER":"keep","progressToken":1}}`,
	)

	got, err = injectMeta(nil, meta)
	if err != nil {
		t.Fatal(err)
	}
	assertJson(t, got, `{"_meta":{"AWS_REGION":"eu-west-1","OTHER":"x"}}`)

	got, err = injectMeta(jsontext.Value(`[1]`), meta)
	if err != nil {
		t.Fatal(err)
	}
	assertJson(t, got, `[1]`)
}

func TestWithClientCapabilities(t *testing.T) {
	assertJson(
		t,
		withClientCapabilities(jsontext.Value(
			`{"protocolVersion":"2025-06-18","capabilities":{"roots":{"listChanged":true},"sampling":{},"elicitation":{}},"clientInfo":{"name":"c","version":"1"}}`,
		)),
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}`,
	)

	// missing or invalid capabilities become empty
	assertJson(
		t,
		withClientCapabilities(jsontext.Value(`{"protocolVersion":"2025-06-18"}`)),
		`{"protocolVersion":"2025-06-18","capabilities":{}}`,
	)
	assertJson(
		t,
		withClientCapabilities(jsontext.Value(`{"capabilities":[1]}`)),
		`{"capabilities":{}}`,
	)

	// supported capabilities are kept, but only if the client has them
	defer func(saved []string) { clientCapabilities = saved }(clientCapabilities)
	clientCapabilities = []string{"elicitation", "sampling"}
	assertJson(
		t,
		withClientCapabilities(jsontext.Value(
			`{"capabilities":{"roots":{},"elicitation":{"form":{}}}}`,
		)),
		`{"capabilities":{"elicitation":{"form":{}}}}`,
	)
}

func TestServiceAndRegion(t *testing.T) {
	tests := []struct{ host, service, region string }{
		{"aws-mcp.us-east-1.api.aws", "aws-mcp", "us-east-1"},
		{"something.example.com", "something", ""},
		{"localhost", "localhost", ""},
	}
	for _, tt := range tests {
		service, region := serviceAndRegion(tt.host)
		if service != tt.service || region != tt.region {
			t.Errorf(
				"serviceAndRegion(%q) = %q, %q, want %q, %q",
				tt.host, service, region, tt.service, tt.region,
			)
		}
	}
}

func TestWithProfileArg(t *testing.T) {
	tools := []jsontext.Value{
		jsontext.Value(
			`{"name":"aws___run_script","inputSchema":{"type":"object","properties":{"code":{"type":"string"}}}}`,
		),
		jsontext.Value(`{"name":"aws___call_aws","inputSchema":{"type":"object"}}`),
		jsontext.Value(`{"name":"aws___read_documentation","inputSchema":{"type":"object"}}`),
	}
	profiles := []*profile{
		{Profile: Profile{Name: "sb", Account: "Sandbox", Role: "RO"}, region: "eu-west-1"},
		{Profile: Profile{Name: "prod", Account: "Production", Role: "RO"}, region: "us-east-1"},
	}

	got, err := withProfileArg(tools, profiles[:1])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(got, tools, sameJson) {
		t.Error("a single profile shouldn't change the tools")
	}

	got, err = withProfileArg(tools, profiles)
	if err != nil {
		t.Fatal(err)
	}

	arg := func(tool jsontext.Value) map[string]any {
		var parsed struct {
			InputSchema struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"inputSchema"`
		}
		if err := json.Unmarshal(tool, &parsed); err != nil {
			t.Fatal(err)
		}
		return parsed.InputSchema.Properties[profileArg]
	}

	runScript := arg(got[0])
	if runScript == nil {
		t.Fatal("aws___run_script has no aws_profile")
	}
	if enum := runScript["enum"].([]any); len(enum) != 2 || enum[0] != "sb" || enum[1] != "prod" {
		t.Errorf("enum = %v", enum)
	}
	description := runScript["description"].(string)
	if !strings.Contains(description, `default "sb"`) ||
		!strings.Contains(description, "prod (Production/RO, us-east-1)") {
		t.Errorf("description = %q", description)
	}
	if !strings.Contains(string(got[0]), `"code"`) {
		t.Error("existing properties were lost")
	}
	if arg(got[1]) == nil {
		t.Error("aws___call_aws has no aws_profile")
	}
	if arg(got[2]) != nil {
		t.Error("aws___read_documentation shouldn't have aws_profile")
	}
}

func TestTakeProfileArg(t *testing.T) {
	params, name, profileName, err := takeProfileArg(jsontext.Value(
		`{"name":"aws___run_script","arguments":{"code":"x","aws_profile":"prod"}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if name != "aws___run_script" || profileName != "prod" {
		t.Errorf("got %q, %q", name, profileName)
	}
	assertJson(t, params, `{"name":"aws___run_script","arguments":{"code":"x"}}`)

	// ignored for tools that don't use credentials, but still removed
	params, _, profileName, err = takeProfileArg(jsontext.Value(
		`{"name":"aws___read_documentation","arguments":{"aws_profile":"prod"}}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if profileName != "" {
		t.Errorf("profile = %q, want none", profileName)
	}
	assertJson(t, params, `{"name":"aws___read_documentation","arguments":{}}`)

	original := jsontext.Value(`{"name":"aws___run_script","arguments":{"code":"x"}}`)
	params, _, profileName, err = takeProfileArg(original)
	if err != nil || profileName != "" {
		t.Fatalf("got %q, %v", profileName, err)
	}
	assertJson(t, params, string(original))

	if _, _, _, err := takeProfileArg(jsontext.Value(
		`{"name":"aws___run_script","arguments":{"aws_profile":1}}`,
	)); err == nil {
		t.Error("a non-string aws_profile should fail")
	}
}

func TestHandshakeCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "cache.json")
	endpoint := "https://aws-mcp.us-east-1.api.aws/mcp"

	h, err := loadHandshake(path, endpoint)
	if err != nil || h != nil {
		t.Fatalf("missing cache: got %v, %v", h, err)
	}

	saved := newHandshake(endpoint, &initializeResult{
		ProtocolVersion: "2025-06-18",
		Capabilities:    jsontext.Value(`{"tools":{"listChanged":true},"prompts":{}}`),
		ServerInfo:      jsontext.Value(`{"name":"x","version":"1"}`),
		Instructions:    "hello",
	}, map[string][]jsontext.Value{
		"tools/list":   {jsontext.Value(`{"name":"a"}`)},
		"prompts/list": {jsontext.Value(`{"name":"p"}`)},
	})
	if err := saveHandshake(path, saved); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadHandshake(path, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || !loaded.sameAs(saved) || !loaded.listChanged("tools") ||
		loaded.listChanged("prompts") {
		t.Errorf("loaded %+v, want %+v", loaded, saved)
	}

	if other, err := loadHandshake(path, "https://other.example.com/mcp"); err != nil ||
		other != nil {
		t.Errorf("another endpoint's cache: got %v, %v", other, err)
	}

	changed := *loaded
	changed.Lists = map[string][]jsontext.Value{
		"tools/list":   loaded.Lists["tools/list"],
		"prompts/list": {jsontext.Value(`{"name":"q"}`)},
	}
	if changed.sameAs(loaded) || changed.sameList(loaded, "prompts/list") ||
		!changed.sameList(loaded, "tools/list") {
		t.Error("only the prompts should be different")
	}

	// a cache from an older version (which only had tools) is ignored
	if err := os.WriteFile(
		path,
		[]byte(`{"endpoint":"`+endpoint+`","tools":[]}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if old, err := loadHandshake(path, endpoint); err != nil || old != nil {
		t.Errorf("an old cache: got %v, %v", old, err)
	}
}

func assertJson(t *testing.T, got jsontext.Value, want string) {
	t.Helper()
	if !sameJson(got, jsontext.Value(want)) {
		t.Errorf("got %s, want %s", got, want)
	}
}
