package env

import (
	"os"
	"regexp"
	"strings"
)

type Environment struct {
	Entries map[string]string
}

func Current() *Environment {
	return From(os.Environ())
}

func From(env []string) *Environment {
	e := New()
	for _, item := range env {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			e.Entries[parts[0]] = parts[1]
		}
	}
	return e
}

func New() *Environment {
	return &Environment{
		Entries: make(map[string]string),
	}
}

func (e *Environment) Export() string {
	out := ""
	for key, value := range e.Entries {
		out += "export " + key + "=" + quote(value) + "\n"
	}
	return out
}

func (e *Environment) Get(key string) string {
	return e.Entries[key]
}

func (e *Environment) Merge(other *Environment) {
	for key, value := range other.Entries {
		e.Entries[key] = value
	}
}

func (e *Environment) Set(key string, value string) {
	e.Entries[key] = value
}

func (e *Environment) Slice() []string {
	out := make([]string, 0, len(e.Entries))
	for key, value := range e.Entries {
		out = append(out, key+"="+quote(value))
	}
	return out
}

func (e *Environment) String() string {
	out := ""
	for key, value := range e.Entries {
		out += key + "=" + quote(value) + "\n"
	}
	return out
}

func (e *Environment) Unset(key string) {
	delete(e.Entries, key)
}

// see https://github.com/alessio/shellescape/blob/b09271781b1a504d1b88e5b44a28e8159b2efd74/shellescape.go#L32
var escapePattern *regexp.Regexp

func init() {
	escapePattern = regexp.MustCompile(`[^\w@%+=:,./-]`)
}

func quote(s string) string {
	if len(s) == 0 {
		return "''"
	}

	if escapePattern.MatchString(s) {
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}

	return s
}
