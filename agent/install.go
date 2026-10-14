package agent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

var plistTemplate = template.Must(template.New("plist").Funcs(template.FuncMap{
	"xml": func(s string) (string, error) {
		var b bytes.Buffer
		err := xml.EscapeText(&b, []byte(s))
		return b.String(), err
	},
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{xml .Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{xml .Executable}}</string>
		<string>agent</string>{{if .Debug}}
		<string>-debug</string>{{end}}
	</array>
	<key>Sockets</key>
	<dict>
		<key>Listeners</key>
		<dict>
			<key>SockPathName</key>
			<string>{{xml .Socket}}</string>
			<key>SockPathMode</key>
			<integer>384</integer>
		</dict>
	</dict>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ThrottleInterval</key>
	<integer>1</integer>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardErrorPath</key>
	<string>{{xml .Log}}</string>
</dict>
</plist>
`))

type installPaths struct {
	Label      string
	Executable string
	Socket     string
	Log        string
	Plist      string
	// Debug makes the agent log debug messages
	Debug bool
}

// InstallOptions configure the installed agent.
type InstallOptions struct {
	// Debug makes the agent log debug messages.
	Debug bool
}

// Install registers the agent with launchd, replacing any previous install.
// launchd starts the agent when a client first connects to its socket.
func Install(opts InstallOptions) error {
	paths, err := getInstallPaths()
	if err != nil {
		return err
	}
	if paths.Executable, err = executablePath(); err != nil {
		return err
	}
	paths.Debug = opts.Debug

	// the socket lives in a directory that only the user can access
	if err := os.MkdirAll(filepath.Dir(paths.Socket), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(paths.Socket), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Plist), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Log), 0o755); err != nil {
		return err
	}

	var plist bytes.Buffer
	if err := plistTemplate.Execute(&plist, paths); err != nil {
		return err
	}
	if err := os.WriteFile(paths.Plist, plist.Bytes(), 0o644); err != nil {
		return err
	}

	if _, err := unload(paths); err != nil {
		return err
	}

	// bootstrap can fail briefly while a previous instance is still unloading
	for attempt := 1; ; attempt++ {
		out, err := exec.Command("launchctl", "bootstrap", domain(), paths.Plist).CombinedOutput()
		if err == nil {
			break
		}
		if attempt == 5 {
			return fmt.Errorf(
				"launchctl bootstrap failed: %w: %s",
				err,
				strings.TrimSpace(string(out)),
			)
		}
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Printf("Installed agent %s\n  plist:  %s\n  socket: %s\n  log:    %s\n",
		paths.Label, paths.Plist, paths.Socket, paths.Log)
	if paths.Debug {
		fmt.Println("  debug logging is on")
	}
	return nil
}

// Uninstall removes the agent from launchd.
func Uninstall() error {
	paths, err := getInstallPaths()
	if err != nil {
		return err
	}

	loaded, err := unload(paths)
	if err != nil {
		return err
	}
	if !loaded {
		fmt.Printf("Agent %s wasn't loaded\n", paths.Label)
	}

	if err := os.Remove(paths.Plist); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	fmt.Printf("Uninstalled agent %s\n", paths.Label)
	return nil
}

func getInstallPaths() (*installPaths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	socket, err := SocketPath()
	if err != nil {
		return nil, err
	}

	return &installPaths{
		Label:  Label,
		Socket: socket,
		Log:    filepath.Join(home, "Library", "Logs", Label+".log"),
		Plist:  filepath.Join(home, "Library", "LaunchAgents", Label+".plist"),
	}, nil
}

// unload stops the agent and removes it from launchd, if it's loaded, and
// reports whether it was.
func unload(paths *installPaths) (bool, error) {
	target := domain() + "/" + paths.Label

	// print only succeeds for a loaded job
	loaded := exec.Command("launchctl", "print", target).Run() == nil
	if loaded {
		out, err := exec.Command("launchctl", "bootout", target).CombinedOutput()
		if err != nil {
			return true, fmt.Errorf(
				"launchctl bootout failed: %w: %s",
				err,
				strings.TrimSpace(string(out)),
			)
		}
	}

	if err := os.Remove(paths.Socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "failed to remove old socket: %v\n", err)
	}
	return loaded, nil
}

func domain() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}
