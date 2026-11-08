package portscan

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

func TestRange(t *testing.T) {
	tests := []struct {
		name    string
		start   uint16
		end     uint16
		want    []uint16
		wantErr error
	}{
		{
			name:  "single port",
			start: 80,
			end:   80,
			want:  []uint16{80},
		},
		{
			name:  "valid range",
			start: 80,
			end:   83,
			want:  []uint16{80, 81, 82, 83},
		},
		{
			name:    "zero start",
			start:   0,
			end:     10,
			wantErr: ErrInvalidRange,
		},
		{
			name:    "start greater than end",
			start:   100,
			end:     80,
			wantErr: ErrInvalidRange,
		},
		{
			name:  "maximum port",
			start: 65535,
			end:   65535,
			want:  []uint16{65535},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Range(tt.start, tt.end)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestFlexRange(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		want    []uint16
		wantErr error
	}{
		{
			name:    "no arguments",
			args:    nil,
			wantErr: ErrNoPorts,
		},
		{
			name: "single uint16",
			args: []any{uint16(80)},
			want: []uint16{80},
		},
		{
			name: "single int",
			args: []any{443},
			want: []uint16{443},
		},
		{
			name: "uint16 slice",
			args: []any{[]uint16{80, 443, 8080}},
			want: []uint16{80, 443, 8080},
		},
		{
			name: "int slice",
			args: []any{[]int{80, 443, 8080}},
			want: []uint16{80, 443, 8080},
		},
		{
			name: "mixed arguments",
			args: []any{
				uint16(80),
				443,
				[]uint16{8080, 8443},
				[]int{9000, 9001},
			},
			want: []uint16{80, 443, 8080, 8443, 9000, 9001},
		},
		{
			name: "duplicate ports",
			args: []any{
				80,
				uint16(80),
				[]int{80, 443},
			},
			want: []uint16{80, 443},
		},
		{
			name:    "zero uint16",
			args:    []any{uint16(0)},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "zero int",
			args:    []any{0},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "negative int",
			args:    []any{-1},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "int greater than max port",
			args:    []any{65536},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "empty uint16 slice",
			args:    []any{[]uint16{}},
			wantErr: ErrInvalidRange,
		},
		{
			name:    "empty int slice",
			args:    []any{[]int{}},
			wantErr: ErrInvalidRange,
		},
		{
			name:    "invalid element in uint16 slice",
			args:    []any{[]uint16{80, 0}},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "invalid element in int slice",
			args:    []any{[]int{80, -1}},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "unsupported type",
			args:    []any{"80"},
			wantErr: ErrInvalidPort,
		},
		{
			name:    "nil argument",
			args:    []any{nil},
			wantErr: ErrInvalidPort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FlexRange(tt.args...)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}

			if err != nil {
				return
			}

			// FlexRange использует map, поэтому порядок не гарантирован.
			slices.Sort(got)
			slices.Sort(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
