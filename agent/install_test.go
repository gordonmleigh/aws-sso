package agent

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPlistDebug(t *testing.T) {
	for _, debug := range []bool{false, true} {
		var plist bytes.Buffer
		err := plistTemplate.Execute(&plist, &installPaths{
			Label:      "test",
			Executable: "/usr/local/bin/aws-sso",
			Socket:     "/tmp/agent.sock",
			Log:        "/tmp/agent.log",
			Debug:      debug,
		})
		if err != nil {
			t.Fatal(err)
		}

		// it must still be well-formed
		dec := xml.NewDecoder(bytes.NewReader(plist.Bytes()))
		for {
			if _, err := dec.Token(); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("debug %v: invalid plist: %v", debug, err)
				}
				break
			}
		}

		got := strings.Contains(
			plist.String(),
			"<string>agent</string>\n\t\t<string>-debug</string>",
		)
		if got != debug {
			t.Errorf("debug %v: -debug in ProgramArguments is %v\n%s", debug, got, plist.String())
		}
	}
}
