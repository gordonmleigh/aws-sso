//go:build darwin

package darwin

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// listenTemp listens on a socket in a new temporary directory.
func listenTemp(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	// t.TempDir() can be too long for a socket path
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, "test.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	return listener, path
}

func TestPeerRunning(t *testing.T) {
	listener, path := listenTemp(t)

	// a separate process connects, and keeps the connection open until it's
	// killed
	peer := exec.Command("nc", "-U", path)
	stdin, err := peer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Process.Kill() })

	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pid, _, err := CheckPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	if pid != peer.Process.Pid {
		t.Fatalf("peer pid is %d, want %d", pid, peer.Process.Pid)
	}
	if running, err := PeerRunning(conn); err != nil || !running {
		t.Fatalf("got running %v, %v while the peer is running", running, err)
	}

	if err := peer.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = peer.Wait()

	if running, err := PeerRunning(conn); err != nil || running {
		t.Errorf("got running %v, %v after the peer exited", running, err)
	}
}

// The peer's socket can outlive it, if a child inherits it. Then the socket is
// still connected, but the pid in its audit token could be reused.
func TestPeerRunningAfterPeerExitsWithSocketOpen(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3")
	}
	listener, path := listenTemp(t)

	// connect, fork a child that holds the socket, and exit when told to
	script := `
import os, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
child = os.fork()
if child == 0:
    time.sleep(30)
else:
    print(os.getpid(), child, flush=True)
    sys.stdin.readline()
`
	peer := exec.Command("python3", "-c", script, path)
	stdin, err := peer.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := peer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}

	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var parent, child int
	if _, err := fmt.Fscan(bufio.NewReader(stdout), &parent, &child); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })

	// identified while it's running, as the agent does
	pid, _, err := CheckPeer(conn)
	if err != nil {
		t.Fatal(err)
	}
	if pid != parent {
		t.Fatalf("peer pid is %d, want the process that connected (%d)", pid, parent)
	}
	if running, err := PeerRunning(conn); err != nil || !running {
		t.Fatalf("got running %v, %v while the peer is running", running, err)
	}

	stdin.Close()
	_ = peer.Wait()

	if running, err := PeerRunning(conn); err != nil || running {
		t.Errorf(
			"got running %v, %v after the peer exited with its socket still open",
			running,
			err,
		)
	}
}
