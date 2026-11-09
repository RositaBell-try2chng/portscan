package portscan

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name        string
		concurrency uint16
		timeout     time.Duration
		wantErr     error
	}{
		{
			name:        "valid",
			concurrency: 10,
			timeout:     time.Second,
		},
		{
			name:        "zero concurrency",
			concurrency: 0,
			timeout:     time.Second,
			wantErr:     ErrNotInitialized,
		},
		{
			name:        "zero timeout",
			concurrency: 10,
			timeout:     0,
			wantErr:     ErrNotInitialized,
		},
		{
			name:        "negative timeout",
			concurrency: 10,
			timeout:     -time.Second,
			wantErr:     ErrNotInitialized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.concurrency, tt.timeout)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}

			if err != nil {
				if scanner != nil {
					t.Fatal("expected nil scanner")
				}
				return
			}

			if scanner == nil {
				t.Fatal("expected scanner")
			}

			if scanner.cr != tt.concurrency {
				t.Errorf("expected concurrency %d, got %d",
					tt.concurrency, scanner.cr)
			}

			if scanner.tm != tt.timeout {
				t.Errorf("expected timeout %v, got %v",
					tt.timeout, scanner.tm)
			}

			if scanner.pr != "tcp" {
				t.Errorf("expected tcp, got %s", scanner.pr)
			}
		})
	}
}

func TestScanValidation(t *testing.T) {
	scanner, err := NewScanner(5, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	externalErr := errors.New("external error")

	tests := []struct {
		name    string
		scanner *Scanner
		hosts   []string
		ports   []uint16
		err     error
		wantErr error
	}{
		{
			name:    "nil scanner",
			scanner: nil,
			hosts:   []string{"127.0.0.1"},
			ports:   []uint16{80},
			wantErr: ErrNotInitialized,
		},
		{
			name:    "empty hosts",
			scanner: scanner,
			ports:   []uint16{80},
			wantErr: ErrNoHosts,
		},
		{
			name:    "only empty hosts",
			scanner: scanner,
			hosts:   []string{"", ""},
			ports:   []uint16{80},
			wantErr: ErrNoHosts,
		},
		{
			name:    "empty ports",
			scanner: scanner,
			hosts:   []string{"127.0.0.1"},
			wantErr: ErrNoPorts,
		},
		{
			name:    "zero port",
			scanner: scanner,
			hosts:   []string{"127.0.0.1"},
			ports:   []uint16{0},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "zero port among valid ports",
			scanner: scanner,
			hosts:   []string{"127.0.0.1"},
			ports:   []uint16{80, 0, 443},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "external error",
			scanner: scanner,
			hosts:   []string{"127.0.0.1"},
			ports:   []uint16{80},
			err:     externalErr,
			wantErr: externalErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := tt.scanner.Scan(
				context.Background(),
				tt.hosts,
				tt.ports,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}

			if err != nil && results != nil {
				t.Error("expected nil results channel")
			}
		})
	}
}

func TestScanDoesNotModifyPorts(t *testing.T) {
	listener := mustListen(t)
	defer listener.Close()

	port := listenerPort(listener)

	scanner := mustScanner(t, 2, time.Second)

	ports := []uint16{port, 443, 80, port}
	original := append([]uint16(nil), ports...)

	results, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1"},
		ports,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := collect(results); err != nil {
		t.Fatal(err)
	}

	for i := range ports {
		if ports[i] != original[i] {
			t.Fatalf("input ports modified: got %v, want %v", ports, original)
		}
	}
}
