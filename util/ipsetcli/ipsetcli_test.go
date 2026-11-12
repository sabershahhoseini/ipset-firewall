package ipsetcli

import "testing"

func TestMaxElemFor(t *testing.T) {
	tests := []struct {
		n, want int
	}{
		{0, 65536},
		{1, 65536},
		{65535, 65536},
		{65536, 65536},
		{65537, 65537},
		{70000, 70000},
		{1000000, 1000000},
	}
	for _, tt := range tests {
		if got := MaxElemFor(tt.n); got != tt.want {
			t.Errorf("MaxElemFor(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}
