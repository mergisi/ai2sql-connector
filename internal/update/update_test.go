package update

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.1.0", 0},
		{"0.1.0", "0.2.0", -1},
		{"0.2.0", "0.1.9", 1},
		{"0.1.9", "0.1.10", -1}, // not a string comparison
		{"1.0.0", "0.9.9", 1},
		{"v0.1.0", "0.1.0", 0}, // release tags carry a v
		{"0.2", "0.2.0", 0},    // missing parts are zero
		{"0.2.0", "0.2", 0},
		{"1.2.0-beta", "1.2.0", 0}, // pre-release compares on its numeric head
		{"", "0.1.0", -1},
		{"garbage", "0.1.0", -1},
	}
	for _, c := range cases {
		if got := compare(c.a, c.b); got != c.want {
			t.Errorf("compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
