package portscan

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestDoItOpenPort(t *testing.T) {
	listener := mustListen(t)
	defer listener.Close()

	scanner := mustScanner(t, 1, time.Second)

	job := Job{
		Host: "127.0.0.1",
		IP: net.IPAddr{
			IP: net.ParseIP("127.0.0.1"),
		},
		Port: listenerPort(listener),
	}

	result := scanner.doIt(context.Background(), job)

	if result.State != StateOpen {
		t.Fatalf("expected %s, got %s: %v",
			StateOpen, result.State, result.Err)
	}

	if result.Duration < 0 {
		t.Errorf("negative duration: %v", result.Duration)
	}
}

func TestDoItClosedPort(t *testing.T) {
	port := closedPort(t)

	scanner := mustScanner(t, 1, time.Second)

	job := Job{
		Host: "127.0.0.1",
		IP: net.IPAddr{
			IP: net.ParseIP("127.0.0.1"),
		},
		Port: port,
	}

	result := scanner.doIt(context.Background(), job)

	if result.State != StateClosed {
		t.Fatalf("expected %s, got %s: %v",
			StateClosed, result.State, result.Err)
	}
}

func TestDoItCanceled(t *testing.T) {
	scanner := mustScanner(t, 1, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	job := Job{
		Host: "127.0.0.1",
		IP: net.IPAddr{
			IP: net.ParseIP("127.0.0.1"),
		},
		Port: 80,
	}

	result := scanner.doIt(ctx, job)

	if result.State != StateCanceled {
		t.Fatalf("expected %s, got %s",
			StateCanceled, result.State)
	}

	if result.Err == nil {
		t.Fatal("expected error")
	}
}

func TestWhichErr(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		state State
	}{
		{"connection refused", syscall.ECONNREFUSED, StateClosed},
		{"host unreachable", syscall.EHOSTUNREACH, StateUnreachable},
		{"network unreachable", syscall.ENETUNREACH, StateUnreachable},
		{"permission denied", syscall.EACCES, StatePermissionDenied},
		{"operation not permitted", syscall.EPERM, StatePermissionDenied},
		{"generic error", errors.New("generic"), StateError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := whichErr(context.Background(), tt.err)

			if got != tt.state {
				t.Errorf("expected %s, got %s", tt.state, got)
			}
		})
	}
}

func TestWhichErrTimeout(t *testing.T) {
	err := &testTimeoutError{}

	got := whichErr(context.Background(), err)

	if got != StateTimeout {
		t.Fatalf("expected %s, got %s", StateTimeout, got)
	}
}

func TestWhichErrCanceledPriority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := whichErr(ctx, &testTimeoutError{})

	if got != StateCanceled {
		t.Fatalf("expected %s, got %s", StateCanceled, got)
	}
}

type testTimeoutError struct{}

func (e *testTimeoutError) Error() string {
	return "i/o timeout"
}

func (e *testTimeoutError) Timeout() bool {
	return true
}

func (e *testTimeoutError) Temporary() bool {
	return true
}
