package ipsetfw

import "testing"

func TestChangePercent(t *testing.T) {
	tests := []struct {
		added, removed, current, want int
	}{
		{0, 0, 100, 0},
		{10, 0, 100, 10},
		{0, 90, 100, 90},
		{10, 10, 10, 200}, // swapping one list for another of the same size counts both ways
		{1, 2, 3, 100},
		{5, 0, 0, 0}, // no current entries: no percentage
	}
	for _, tt := range tests {
		if got := changePercent(tt.added, tt.removed, tt.current); got != tt.want {
			t.Errorf("changePercent(+%d -%d of %d) = %d, want %d", tt.added, tt.removed, tt.current, got, tt.want)
		}
	}
}
