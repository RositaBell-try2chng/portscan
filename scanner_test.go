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

 func TestScanOpenAndClosedPorts(t *testing.T) {
	listener := mustListen(t)
	defer listener.Close()

	openPort := listenerPort(listener)

	closedListener := mustListen(t)
	closedPort := listenerPort(closedListener)
	closedListener.Close()

	scanner := mustScanner(t, 2, time.Second)

	results, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1"},
		[]uint16{openPort, closedPort},
	)
	if err != nil {
		t.Fatal(err)
	}

	got := make(map[uint16]State)

	for result := range results {
		got[result.Port] = result.State
	}

	// Проверяем состояние открытого порта.
	if state := got[openPort]; state != StateOpen {
		t.Errorf("port %d: expected %q, got %q",
			openPort, StateOpen, state)
	}

	// Проверяем состояние закрытого порта.
	if state := got[closedPort]; state != StateClosed {
		t.Errorf("port %d: expected %q, got %q",
			closedPort, StateClosed, state)
	}

	// Проверяем количество результатов.
	if len(got) != 2 {
		t.Errorf("expected 2 results, got %d", len(got))
	}
}

func TestScanContextCancellation(t *testing.T) {
	listener := mustListen(t)
	defer listener.Close()

	port := listenerPort(listener)

	scanner := mustScanner(t, 1, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Создаём большое количество заданий,
	// чтобы сканирование продолжалось после первого результата.
	hosts := make([]string, 10000)
	for i := range hosts {
		hosts[i] = "127.0.0.1"
	}

	results, err := scanner.Scan(
		ctx,
		hosts,
		[]uint16{port},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Ждём первый результат.
	select {
	case result, ok := <-results:
		if !ok {
			t.Fatal("results channel closed before first result")
		}

		if result.State != StateOpen {
			t.Fatalf("expected %q, got %q",
				StateOpen, result.State)
		}

	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for first result")
	}

	// Отменяем контекст во время сканирования.
	cancel()

	// Проверяем, что канал результатов закрылся.
	done := make(chan struct{})

	go func() {
		for range results {
		}
		close(done)
	}()

	select {
	case <-done:
		// Все worker завершились, канал закрыт.

	case <-time.After(3 * time.Second):
		t.Fatal("results channel was not closed after context cancellation")
	}
}