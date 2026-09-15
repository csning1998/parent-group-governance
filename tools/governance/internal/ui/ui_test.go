package ui

import (
	"bufio"
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestPrintRoutesErrorAndFatalToErrOut(t *testing.T) {
	cases := []struct {
		name      string
		level     Level
		wantOnErr bool
	}{
		{"Info", Info, false},
		{"OK", OK, false},
		{"Error", Error, true},
		{"Fatal", Fatal, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertPrintRouting(t, tc.level, tc.wantOnErr)
		})
	}
}

// assertPrintRouting prints one message at level and asserts the message lands on exactly one
// of the two streams.
func assertPrintRouting(t *testing.T, level Level, wantOnErr bool) {
	t.Helper()
	var out, errOut bytes.Buffer
	New(&out, &errOut).Print(level, "hello")

	written, quiet := &out, &errOut
	if wantOnErr {
		written, quiet = &errOut, &out
	}
	if !strings.Contains(written.String(), "hello") {
		t.Errorf("Print(%v) wrote nothing to the expected stream", level)
	}
	if quiet.Len() != 0 {
		t.Errorf("Print(%v) also wrote to the other stream: %q", level, quiet.String())
	}
}

func TestConfirmAcceptsYAndyOnly(t *testing.T) {
	cases := map[string]bool{"Y\n": true, "y\n": true, "yes\n": false, "n\n": false, "\n": false}
	for input, want := range cases {
		var out, errOut bytes.Buffer
		got := New(&out, &errOut).PromptConfirm(bufio.NewReader(strings.NewReader(input)), "confirm?")
		if got != want {
			t.Errorf("PromptConfirm(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestPromptSecretReadsLineWhenFdIsNotATerminal(t *testing.T) {
	var out, errOut bytes.Buffer
	got, err := New(&out, &errOut).PromptSecret(bufio.NewReader(strings.NewReader("hidden-value\n")), -1, "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		t.Fatalf("PromptSecret: %v", err)
	}
	if got != "hidden-value" {
		t.Errorf("PromptSecret = %q, want %q", got, "hidden-value")
	}
	if strings.Contains(out.String(), "hidden-value") {
		t.Errorf("PromptSecret wrote the secret to out: %q", out.String())
	}
}

func TestPromptSecretDisablesEchoOnTerminal(t *testing.T) {
	origIsTerminal := isTerminalFn
	origReadPassword := readPasswordFn
	t.Cleanup(func() {
		isTerminalFn = origIsTerminal
		readPasswordFn = origReadPassword
	})
	isTerminalFn = func(int) bool { return true }
	readPasswordFn = func(int) ([]byte, error) { return []byte("tty-secret"), nil }

	var out, errOut bytes.Buffer
	got, err := New(&out, &errOut).PromptSecret(bufio.NewReader(strings.NewReader("must-not-read\n")), 0, "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		t.Fatalf("PromptSecret: %v", err)
	}
	if got != "tty-secret" {
		t.Errorf("PromptSecret = %q, want %q", got, "tty-secret")
	}
	if strings.Contains(out.String(), "tty-secret") {
		t.Errorf("PromptSecret wrote the secret to out: %q", out.String())
	}
}

func TestSelectValidChoice(t *testing.T) {
	var out, errOut bytes.Buffer
	index, ok := New(&out, &errOut).PromptSelect(bufio.NewReader(strings.NewReader("2\n")), "choose", []string{"a", "b", "c"})
	if !ok || index != 1 {
		t.Errorf("PromptSelect(\"2\") = (%d, %v), want (1, true)", index, ok)
	}
}

func TestMultiSelectAcceptsCommaAndSpaceSeparatedChoices(t *testing.T) {
	options := []string{"a", "b", "c", "d"}
	cases := map[string][]int{
		"1,3,4\n":   {0, 2, 3},
		"1 2 3\n":   {0, 1, 2},
		"1, 2  3\n": {0, 1, 2},
		"1,1,2\n":   {0, 1},
	}
	for input, want := range cases {
		var out, errOut bytes.Buffer
		got, ok := New(&out, &errOut).PromptMultiSelect(bufio.NewReader(strings.NewReader(input)), "choose", options)
		if !ok {
			t.Errorf("PromptMultiSelect(%q) ok = false, want true", input)
			continue
		}
		if !slices.Equal(got, want) {
			t.Errorf("PromptMultiSelect(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestMultiSelectRejectsInvalidInput(t *testing.T) {
	options := []string{"a", "b", "c"}
	cases := []string{"\n", "1,5\n", "1,x\n", "0\n"}
	for _, input := range cases {
		var out, errOut bytes.Buffer
		_, ok := New(&out, &errOut).PromptMultiSelect(bufio.NewReader(strings.NewReader(input)), "choose", options)
		if ok {
			t.Errorf("PromptMultiSelect(%q) ok = true, want false", input)
		}
	}
}
