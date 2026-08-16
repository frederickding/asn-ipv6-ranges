package main

import "testing"

func TestParseASN(t *testing.T) {
	tests := []struct {
		in        string
		wantValue uint64
		wantCanon string
		wantErr   bool
	}{
		{in: "2906", wantValue: 2906, wantCanon: "2906"},
		{in: "0", wantValue: 0, wantCanon: "0"},
		{in: "65535", wantValue: 65535, wantCanon: "65535"},
		{in: "4294967295", wantValue: 4294967295, wantCanon: "4294967295"},
		{in: "007", wantValue: 7, wantCanon: "7"},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "29a6", wantErr: true},
		{in: "-5", wantErr: true},
		{in: "4294967296", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, canon, err := parseASN(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %d/%q", tt.in, v, canon)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v != tt.wantValue || canon != tt.wantCanon {
				t.Errorf("got %d/%q, want %d/%q", v, canon, tt.wantValue, tt.wantCanon)
			}
		})
	}
}

// isPermittedASN delegates to internal/asnreg, which owns the exhaustive table
// tests; these cases pin the behavior the handler depends on, including the
// 16-bit reserved ranges that are now rejected.
func TestIsPermittedASN(t *testing.T) {
	tests := []struct {
		name string
		asn  uint64
		want bool
	}{
		{"typical 16-bit", 2906, true},
		{"first assigned 16-bit", 1, true},
		{"AS0 is reserved", 0, false},
		{"AS_TRANS is reserved", 23456, false},
		{"documentation range", 64500, false},
		{"private use start", 64512, false},
		{"private use end", 65534, false},
		{"AS65535 is reserved", 65535, false},
		{"reserved 32-bit block", 100000, false},
		{"first APNIC 32-bit block", 131072, true},
		{"unallocated after APNIC", 155962, false},
		{"first RIPE 32-bit block", 196608, true},
		{"reserved for private use", 4200000001, false},
		{"final reserved value", 4294967295, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPermittedASN(tt.asn); got != tt.want {
				t.Errorf("isPermittedASN(%d) = %v, want %v", tt.asn, got, tt.want)
			}
		})
	}
}
