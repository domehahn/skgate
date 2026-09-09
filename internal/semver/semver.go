package semver

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct{ Major, Minor, Patch int }

func Parse(s string) (Version, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core := strings.SplitN(s, "-", 2)[0]
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("expected semantic version x.y.z, got %q", s)
	}
	vals := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("invalid semantic version %q", s)
		}
		vals[i] = n
	}
	return Version{vals[0], vals[1], vals[2]}, nil
}

func Compare(a, b Version) int {
	av := []int{a.Major, a.Minor, a.Patch}
	bv := []int{b.Major, b.Minor, b.Patch}
	for i := range av {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}
