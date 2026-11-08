package portscan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
	"sync"
)

func createTestScanner(t *testing.T) *Scanner {
	t.Helper()

	scanner, err := NewScanner(10, time.Second)
	if err != nil {
		t.Fatalf("NewScanner() error: %v", err)
	}

	return scanner
}

func startTestServer(t *testing.T, pr string, ip string) (net.Listener, uint16) {
	t.Helper()

	listener, err := net.Listen(pr, ip)
	if err != nil {
		t.Fatalf("failed to start TCP server: %v", err)
	}

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	return listener, port
}

// Проверка создания сканера.
func TestNewScanner(t *testing.T) {
	tests := []struct {
		name        string
		concurrency uint16
		timeout     time.Duration
		wantErr     bool
	}{
		{
			name:        "valid settings",
			concurrency: 10,
			timeout:     time.Second,
		},
		{
			name:        "zero concurrency",
			concurrency: 0,
			timeout:     time.Second,
			wantErr:     true,
		},
		{
			name:        "zero timeout",
			concurrency: 10,
			timeout:     0,
			wantErr:     true,
		},
		{
			name:        "negative timeout",
			concurrency: 10,
			timeout:     -time.Second,
			wantErr:     true,
		},
		{
			name:        "invalid concurrency and timeout",
			concurrency: 0,
			timeout:     0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.concurrency, tt.timeout)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr = %v", err, tt.wantErr)
			}

			if !tt.wantErr && scanner == nil {
				t.Fatal("expected non-nil scanner")
			}
		})
	}
}

// Проверка обнаружения открытого порта.
func TestScanOpenPort(t *testing.T) {
	listener, port := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer listener.Close()

	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	result := results[0]

	if result.State != "open" {
		t.Errorf("expected open, got %v", result.State)
	}

	if result.Port != port {
		t.Errorf("expected port %d, got %d", port, result.Port)
	}

	if result.Host != "127.0.0.1" {
		t.Errorf("unexpected host: %s", result.Host)
	}

	if result.IP == nil || !result.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("unexpected IP: %v", result.IP)
	}

	if result.Duration < 0 {
		t.Errorf("negative duration: %v", result.Duration)
	}
}

// Проверка обнаружения закрытого порта.
func TestScanClosedPort(t *testing.T) {
	listener, port := startTestServer(t, "tcp4", "127.0.0.1:0")

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].State != "closed" {
		t.Errorf("expected closed, got %v", results[0].State)
	}
}

// Проверка нескольких портов одного хоста.
func TestScanMultiplePorts(t *testing.T) {
	server1, port1 := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer server1.Close()

	server2, port2 := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer server2.Close()

	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{port1, port2},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, result := range results {
		if result.State != "open" {
			t.Errorf("port %d: expected open, got %v", result.Port, result.State)
		}
	}
}

// Проверка нескольких IP-адресов.
func TestScanMultipleHosts(t *testing.T) {
	server1, port1 := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer server1.Close()

	server2, port2 := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer server2.Close()

	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1", "127.0.0.2"},
		[]uint16{port1, port2},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
}

// Проверка дедупликации IP.
func TestScanDuplicateIP(t *testing.T) {
	listener, port := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer listener.Close()

	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{
			"127.0.0.1",
			"localhost",
			"127.0.0.1",
		},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	seen := make(map[string]bool)

	for _, result := range results {
		if result.IP == nil {
			t.Fatal("result IP is nil")
		}

		ip := result.IP.String()

		if seen[ip] {
			t.Errorf("duplicate IP scanned: %s", ip)
		}

		seen[ip] = true
	}
}

// Проверка нескольких IP, полученных из одного hostname.
func TestScanHostnameMultipleIPs(t *testing.T) {
	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"localhost"},
		[]uint16{80},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}

	seen := make(map[string]bool)

	for _, result := range results {
		if result.IP == nil {
			t.Fatal("result IP is nil")
		}

		ip := result.IP.String()

		if seen[ip] {
			t.Errorf("duplicate IP: %s", ip)
		}

		seen[ip] = true

		if result.Host != "localhost" {
			t.Errorf("expected hostname localhost, got %s", result.Host)
		}
	}
}

// Проверка пустого списка хостов.
func TestScanEmptyHosts(t *testing.T) {
	scanner := createTestScanner(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	_, err := scanner.Scan(
		ctx,
		nil,
		[]uint16{80},
	)

	if err == nil {
		t.Fatal("expected error for empty hosts")
	}
}

// Проверка пустого списка портов.
func TestScanEmptyPorts(t *testing.T) {
	scanner := createTestScanner(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	_, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		nil,
	)

	if err == nil {
		t.Fatal("expected error for empty ports")
	}
}

// Проверка некорректного hostname.
func TestScanInvalidHost(t *testing.T) {
	scanner := createTestScanner(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	res, _ := scanner.Scan(
		ctx,
		[]string{"invalid host !!!"},
		[]uint16{80},
	)

	if len(res) < 1 {
		t.Fatal("not enogh results for TestScanInvalidHost")
	}

	if res[0].State != "error" {
		t.Fatal("expected error for invalid host")
	}
}

// // Проверка неразрешимого DNS-имени.
// func TestScanUnresolvableHost(t *testing.T) {
// 	scanner := createTestScanner(t)
	
// 	ctx, cancel := context.WithTimeout(
// 		context.Background(),
// 		30*time.Second,
// 	)
// 	defer cancel()

// 	res, _ := scanner.Scan(
// 		ctx,
// 		[]string{"this-host-does-not-exist.invalid"},
// 		[]uint16{80},
// 	)

// 	if res[0].State != "error" {
// 		t.Fatal("expected error for unresolvable hostname")
// 	}
// }

// Проверка отменённого контекста.
func TestScanCanceledContext(t *testing.T) {
	scanner := createTestScanner(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)

	cancel()

	_, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{80},
	)

	if err == nil {
		t.Fatal("expected cancellation error")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// Проверка повторного использования сканера.
func TestScannerReuse(t *testing.T) {
	listener, port := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer listener.Close()

	scanner := createTestScanner(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	for i := 0; i < 5; i++ {
		results, err := scanner.Scan(
			ctx,
			[]string{"127.0.0.1"},
			[]uint16{port},
		)
		if err != nil {
			t.Fatalf("Scan #%d error: %v", i, err)
		}

		if len(results) != 1 {
			t.Fatalf("Scan #%d: expected 1 result, got %d", i, len(results))
		}
	}
}

// Проверка одновременного использования одного сканера.
func TestConcurrentScan(t *testing.T) {
	listener, port := startTestServer(t, "tcp4", "127.0.0.1:0")
	defer listener.Close()

	scanner := createTestScanner(t)

	const workers = 10

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(
				context.Background(),
				30*time.Second,
			)
			defer cancel()

			results, err := scanner.Scan(
				ctx,
				[]string{"127.0.0.1"},
				[]uint16{port},
			)
			if err != nil {
				t.Errorf("Scan() error: %v", err)
				return
			}

			if len(results) != 1 {
				t.Errorf("expected 1 result, got %d", len(results))
			}
		}()
	}

	wg.Wait()
}

// Проверка IPv6.
func TestScanIPv6(t *testing.T) {
	listener, port := startTestServer(t, "tcp6", "[::1]:0")
	defer listener.Close()

	scanner := createTestScanner(t)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"::1"},
		[]uint16{port},
	)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].State != "open" {
		t.Errorf("expected open, got %v", results[0].State)
	}
}



