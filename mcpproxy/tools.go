package mcpproxy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
)

// Profile is an account and role that tool calls can be signed with.
type Profile struct {
	// Name is how the profile is chosen with the aws_profile tool argument.
	Name string
	// Account is the account ID or name.
	Account string
	Role    string
	// Region is the AWS_REGION for this profile, if it has its own.
	Region string
}

const profileArg = "aws_profile"

// authTools are the tools that use AWS credentials, so can be switched to
// another profile.
var authTools = map[string]bool{
	"aws___call_aws":             true,
	"aws___run_script":           true,
	"aws___get_presigned_url":    true,
	"aws___get_tasks":            true,
	"aws___suggest_aws_commands": true,
}

// withProfileArg adds the aws_profile argument to the tools in authTools.
func withProfileArg(tools []jsontext.Value, profiles []*profile) ([]jsontext.Value, error) {
	if len(profiles) < 2 {
		return tools, nil
	}

	names := make([]string, 0, len(profiles))
	descriptions := make([]string, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.Name)
		descriptions = append(descriptions, describeProfile(p))
	}
	arg, err := json.Marshal(map[string]any{
		"type": "string",
		"enum": names,
		"description": fmt.Sprintf(
			"AWS account and role to use (default %q): %s.",
			profiles[0].Name,
			strings.Join(descriptions, "; "),
		),
	})
	if err != nil {
		return nil, err
	}

	result := make([]jsontext.Value, 0, len(tools))
	for _, tool := range tools {
		updated, err := addProfileArg(tool, arg)
		if err != nil {
			return nil, err
		}
		result = append(result, updated)
	}
	return result, nil
}

// describeProfile returns e.g. `prod (Production/ReadOnlyAccess, us-east-1)`.
func describeProfile(p *profile) string {
	if p.region == "" {
		return fmt.Sprintf("%s (%s/%s)", p.Name, p.Account, p.Role)
	}
	return fmt.Sprintf("%s (%s/%s, %s)", p.Name, p.Account, p.Role, p.region)
}

func addProfileArg(tool jsontext.Value, arg jsontext.Value) (jsontext.Value, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(tool, &fields); err != nil {
		return nil, err
	}

	var name string
	if err := json.Unmarshal(fields["name"], &name); err != nil || !authTools[name] {
		return tool, nil
	}

	schema := map[string]jsontext.Value{}
	if raw, ok := fields["inputSchema"]; ok {
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, err
		}
	}
	properties := map[string]jsontext.Value{}
	if raw, ok := schema["properties"]; ok {
		if err := json.Unmarshal(raw, &properties); err != nil {
			return nil, err
		}
	}

	properties[profileArg] = arg

	var err error
	if schema["properties"], err = json.Marshal(properties); err != nil {
		return nil, err
	}
	if fields["inputSchema"], err = json.Marshal(schema); err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

// takeProfileArg removes aws_profile from the arguments of a tools/call
// request, and returns the tool name and profile name (empty if not given).
func takeProfileArg(params jsontext.Value) (jsontext.Value, string, string, error) {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(params, &fields); err != nil {
		return nil, "", "", err
	}

	var name string
	if err := json.Unmarshal(fields["name"], &name); err != nil {
		return nil, "", "", fmt.Errorf("invalid tool name: %w", err)
	}

	raw, ok := fields["arguments"]
	if !ok || raw.Kind() != '{' {
		return params, name, "", nil
	}
	var arguments map[string]jsontext.Value
	if err := json.Unmarshal(raw, &arguments); err != nil {
		return nil, "", "", err
	}
	rawProfile, ok := arguments[profileArg]
	if !ok {
		return params, name, "", nil
	}

	var profileName string
	if err := json.Unmarshal(rawProfile, &profileName); err != nil {
		return nil, "", "", fmt.Errorf("%s must be a string", profileArg)
	}
	delete(arguments, profileArg)

	var err error
	if fields["arguments"], err = json.Marshal(arguments); err != nil {
		return nil, "", "", err
	}
	params, err = json.Marshal(fields)
	if err != nil {
		return nil, "", "", err
	}

	if !authTools[name] {
		// it doesn't apply, so don't let it fail the call
		profileName = ""
	}
	return params, name, profileName, nil
}
