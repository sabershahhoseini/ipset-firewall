package netutils

import (
	"reflect"
	"testing"
)

func TestMergeIPsToCIDRs(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"empty input", nil, nil},
		{"blank lines only", []string{"", "  ", "\r"}, nil},
		{"bare IP becomes /32", []string{"1.1.1.1"}, []string{"1.1.1.1/32"}},
		{"CIDR kept", []string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}},
		{"CRLF line trimmed", []string{"1.1.1.1\r"}, []string{"1.1.1.1/32"}},
		{"garbage skipped", []string{"garbage"}, nil},
		{"invalid prefix skipped", []string{"1.2.3.4/99"}, nil},
		{"IPv6 skipped", []string{"2001:db8::/32"}, nil},
		{"duplicates collapse", []string{"1.1.1.1", "1.1.1.1"}, []string{"1.1.1.1/32"}},
		{"adjacent ranges merge", []string{"10.0.0.0/25", "10.0.0.128/25"}, []string{"10.0.0.0/24"}},
		{"valid entries survive invalid ones", []string{"garbage", "10.0.0.1", "", "1.2.3.4/99"}, []string{"10.0.0.1/32"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeIPsToCIDRs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MergeIPsToCIDRs(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCIDRValid(t *testing.T) {
	tests := []struct {
		input     string
		want      string
		wantValid bool
	}{
		{"1.1.1.1", "1.1.1.1/32", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"garbage", "", false},
		{"1.2.3.4/99", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := IsCIDRValid(tt.input)
		if got != tt.want || ok != tt.wantValid {
			t.Errorf("IsCIDRValid(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.wantValid)
		}
	}
}
