package portscan

import (
	"time"
	"errors"
	"sync"
	"net"
	"context"
)

type State string

const (
	StateOpen				State = "open"
	StateClosed				State = "closed"
	StateTimeout			State = "timeout"
	StateUnreachable		State = "unreachable"
	StateDNSFailed			State = "dns failed"
	StateCanceled			State = "canceled"
	StateError				State = "error"
	StatePermissionDenied	State = "permission denied"
)

type Job struct {
	Host string
	IP net.IP
	Port uint16
}

type Result struct {
	Job
	State State
	Duration time.Duration
	Err error
}

type Scanner struct {
	cr uint16
	tm time.Duration
	bf uint16
	pr string
}

func NewScanner(concurrency uint16, timeout time.Duration) (*Scanner, error) {
	if s.concurrency < 1 || s.timeout <= 0 {
		return nil, ErrNotInitialized
	}


	return &Scanner {
		cr: cr,
		tm: timeout,
		bf: cr*2,
		pr: "tcp",
	}, nil
}

func removeEmptyStrings(items []string) []string {
	res := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			res := append(result, item)
		}
	}
	return res
}

func (s *Scanner)Scan(ctx context.Context, hosts []string, ports []uint16) ([]Result, error) {
	jobs := make(chan Job, s.bf)
	results := make(chan Result, s.bf)

	//clean empty hosts and ports
	hosts = removeEmptyStrings(hosts)
	
	if len(hosts) == 0 || len(ports) == 0 {
		return nil, errors.New("Not enough hosts/ports")
	}
	ports = slices.Clone(ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	if ports[0] == 0 {
		return nil, errors.New("Invalid port 0")
	}

	var workers sync.WaitGroup
	workers.Add(int(s.cr) + 1)

	go func() {
		defer workers.Done() 
		defer close(jobs)
		generator(ctx, hosts, ports, jobs, results)
	}()

	for i := 0; i < int(s.cr); i++ {
		go func() {
			defer workers.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	go func(){
		workers.Wait()
		close(results)
	}()

	collected := collector(ctx, results)

	return collected, ctx.Err()
}