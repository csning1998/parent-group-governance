package secretgen

import (
	"testing"
	"unicode"
)

func TestGenerateContainsEveryRequiredCharClass(t *testing.T) {
	for i := 0; i < 20; i++ {
		got, err := Generate(24, Upper, Lower, Digit, Special)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(got) != 24 {
			t.Fatalf("len(got) = %d, want 24", len(got))
		}
		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, r := range got {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			default:
				hasSpecial = true
			}
		}
		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
			t.Fatalf("Generate() = %q, missing a required character class (upper=%v lower=%v digit=%v special=%v)",
				got, hasUpper, hasLower, hasDigit, hasSpecial)
		}
	}
}

func TestGenerateLengthClampsToClassCount(t *testing.T) {
	cases := []struct {
		name    string
		length  int
		classes []CharClass
		wantLen int
	}{
		{"positive below class count", 1, []CharClass{Upper, Lower, Digit, Special}, 4},
		{"zero", 0, []CharClass{Upper, Lower, Digit, Special}, 4},
		{"negative", -5, []CharClass{Upper, Lower}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Generate(c.length, c.classes...)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(got) != c.wantLen {
				t.Errorf("len(got) = %d, want %d (clamped to class count)", len(got), c.wantLen)
			}
		})
	}
}

func TestGenerateNoClassesErrors(t *testing.T) {
	if _, err := Generate(10); err == nil {
		t.Fatal("Generate with no classes: want error, got nil")
	}
}

func TestGenerateProducesDistinctValues(t *testing.T) {
	a, err := Generate(24, Upper, Lower, Digit, Special)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate(24, Upper, Lower, Digit, Special)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a == b {
		t.Error("two Generate calls returned the same value; expected fresh randomness")
	}
}
