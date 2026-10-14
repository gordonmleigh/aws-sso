package mcpproxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// errStopEvents can be returned by the readEvents callback to stop reading.
var errStopEvents = errors.New("stop reading events")

// readEvents calls fn with the data of each server-sent event in r, until r is
// exhausted or fn returns an error. Event types, ids and retry hints are
// ignored.
func readEvents(r io.Reader, fn func(data []byte) error) error {
	reader := bufio.NewReader(r)
	var data []byte
	hasData := false

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		atEOF := err != nil

		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))

		if len(line) == 0 {
			// a blank line ends the event; so does the end of the stream
			if hasData {
				if err := fn(data); err != nil {
					if errors.Is(err, errStopEvents) {
						return nil
					}
					return err
				}
			}
			data = nil
			hasData = false
		} else if field, value, _ := bytes.Cut(line, []byte(":")); string(field) == "data" {
			value = bytes.TrimPrefix(value, []byte(" "))
			if hasData {
				data = append(data, '\n')
			}
			data = append(data, value...)
			hasData = true
		}

		if atEOF {
			// the stream ended without a blank line after the last event
			if hasData {
				if err := fn(data); err != nil && !errors.Is(err, errStopEvents) {
					return err
				}
			}
			return nil
		}
	}
}
