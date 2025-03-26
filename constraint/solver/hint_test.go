package solver

import "testing"

func TestRegexpRename(t *testing.T) {
	for i, v := range []struct{ input, expected string }{
		// conversion from new to old style
		{"github.com/arithmic/gnark/internal/regression_tests/issue1045.init.func1", "github.com/arithmic/gnark/internal/regression_tests/issue1045.glob..func1"},
		// conversion from old to old same
		{"github.com/arithmic/gnark/internal/regression_tests/issue1045.glob..func1", "github.com/arithmic/gnark/internal/regression_tests/issue1045.glob..func1"},
		// conversion from explicit to explicit same
		{"github.com/arithmic/gnark/internal/regression_tests/issue1045.ExplicitHint", "github.com/arithmic/gnark/internal/regression_tests/issue1045.ExplicitHint"},
	} {
		if got := newToOldStyle(v.input); got != v.expected {
			t.Errorf("test %d: expected %s, got %s", i, v.expected, got)
		}
	}

}
