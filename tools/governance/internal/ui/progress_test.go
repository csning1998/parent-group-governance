package ui

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func TestProgressBarRendersInteractiveBarAndClearsOnFinish(t *testing.T) {
	var buf syncBuffer
	bar := NewProgressBar(&buf, true)
	bar.Update(1, 3, "terraform.foundation_vault_bastion")
	time.Sleep(100 * time.Millisecond)
	bar.Update(3, 3, "terraform.group_ai_provider_azure")
	bar.Finish()
	bar.Finish()
	bar.Update(3, 3, "ignored-after-finish")

	out := buf.String()
	for _, want := range []string{
		"1/3",
		"terraform.foundation_vault_bastion",
		"3/3",
		"terraform.group_ai_provider_azure",
		"\r\033[2K",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("progress output missing %q:\n%q", want, out)
		}
	}
	if strings.Contains(out, "ignored-after-finish") {
		t.Errorf("Update after Finish wrote unexpected output: %q", out)
	}
}

func TestProgressBarSilentWhenNonInteractive(t *testing.T) {
	var buf syncBuffer
	bar := NewProgressBar(&buf, false)
	bar.Update(1, 2, "host.tools")
	bar.Finish()
	if buf.Len() != 0 {
		t.Errorf("non-interactive progress bar wrote %q, want empty", buf.String())
	}
}

func TestIsTerminalWriterDetectsFileTerminal(t *testing.T) {
	if IsTerminalWriter(&bytes.Buffer{}) {
		t.Errorf("IsTerminalWriter(&bytes.Buffer{}) = true, want false")
	}

	origIsTerminal := isTerminalFn
	t.Cleanup(func() { isTerminalFn = origIsTerminal })
	isTerminalFn = func(int) bool { return true }

	if !IsTerminalWriter(os.Stderr) {
		t.Errorf("IsTerminalWriter(os.Stderr) = false when terminal, want true")
	}
}

func TestComputeFilledWidthBounds(t *testing.T) {
	cases := []struct {
		current, total, width, want int
	}{
		{0, 0, 20, 0},
		{-1, 5, 20, 0},
		{1, 4, 20, 5},
		{10, 5, 20, 20},
	}
	for _, tc := range cases {
		if got := computeFilledWidth(tc.current, tc.total, tc.width); got != tc.want {
			t.Errorf("computeFilledWidth(%d, %d, %d) = %d, want %d", tc.current, tc.total, tc.width, got, tc.want)
		}
	}
}
