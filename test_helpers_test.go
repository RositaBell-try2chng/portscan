package portscan

import (
	"net"
	"testing"
	"time"
	"errors"
)

func mustListen(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	return listener
}

func listenerPort(listener net.Listener) uint16 {
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func closedPort(t *testing.T) uint16 {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	port := listenerPort(listener)

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	return port
}

func mustScanner(t *testing.T, concurrency uint16, timeout time.Duration) *Scanner {
	t.Helper()

	scanner, err := NewScanner(concurrency, timeout)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	return scanner
}

func collect(results <-chan Result) ([]Result, error) {
	var collected []Result

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		select {
		case result, ok := <-results:
			if !ok {
				return collected, nil
			}

			collected = append(collected, result)

		case <-timer.C:
			return nil, errors.New("timeout waiting for results")
		}
	}
}
