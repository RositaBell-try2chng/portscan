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

func NewScanner(cr uint16, timeout time.Duration) (*Scanner, error) {
	if cr < 1 {
		return nil, errors.New("concurrency less than 1")
	}

	if timeout <= 0 {
		return nil, errors.New("timeout less than 0")
	}

	return &Scanner {
		cr: cr,
		tm: timeout,
		bf: cr*2,
		pr: "tcp",
	}, nil
}

func (s *Scanner) SetConcurrency(cr uint16) error {
	if cr < 1 {
		return errors.New("concurrency less than 1")
	}
	s.cr = cr
	s.bf = cr*2
	return nil
}

func (s *Scanner) SetTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("timeout less than 0")
	}
	s.tm = timeout
	return nil
}

func (s *Scanner) GetSettings() (uint16, time.Duration) {
	return s.cr, s.tm
}

func (s *Scanner)Scan(ctx context.Context, hosts []string, ports []uint16) ([]Result, error) {
	jobs := make(chan Job, s.bf)
	results := make(chan Result, s.bf)

	if len(hosts) == 0 || len(ports) == 0 {
		return nil, errors.New("Not enough hosts/ports")
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