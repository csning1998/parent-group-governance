package ui

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	progressBarWidth   = 20
	progressTickPeriod = 80 * time.Millisecond
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ProgressBar renders a single-line interactive progress bar for long-running operations.
type ProgressBar struct {
	out         io.Writer
	interactive bool
	startedAt   time.Time

	mu       sync.Mutex
	current  int
	total    int
	label    string
	spinIdx  int
	finished bool

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// IsTerminalWriter reports whether w is an *os.File connected to an interactive terminal.
func IsTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isTerminalFn(int(f.Fd()))
}

// ShouldUseColor reports whether ANSI colors should be emitted to w following NO_COLOR and CLICOLOR_FORCE.
func ShouldUseColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if force := os.Getenv("CLICOLOR_FORCE"); force != "" && force != "0" {
		return true
	}
	return IsTerminalWriter(w)
}

// NewProgressBar creates a progress bar targeting w. Non-interactive bars emit no terminal escape sequences.
func NewProgressBar(w io.Writer, interactive bool) *ProgressBar {
	bar := &ProgressBar{
		out:         w,
		interactive: interactive && w != nil,
		startedAt:   time.Now(),
		stopCh:      make(chan struct{}),
	}
	if bar.interactive {
		bar.wg.Add(1)
		go bar.runTicker()
	}
	return bar
}

// Update advances the displayed progress to current/total and sets the active item label.
func (p *ProgressBar) Update(current, total int, label string) {
	if p == nil || !p.interactive {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.current = current
	p.total = total
	p.label = label
	p.spinIdx = (p.spinIdx + 1) % len(spinnerFrames)
	p.renderLocked()
}

// Finish stops the background ticker and erases the interactive progress line.
func (p *ProgressBar) Finish() {
	if p == nil || !p.interactive {
		return
	}
	p.mu.Lock()
	if p.finished {
		p.mu.Unlock()
		return
	}
	p.finished = true
	close(p.stopCh)
	p.mu.Unlock()

	p.wg.Wait()

	p.mu.Lock()
	writef(p.out, "\r\033[2K")
	p.mu.Unlock()
}

func (p *ProgressBar) runTicker() {
	defer p.wg.Done()
	ticker := time.NewTicker(progressTickPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			if !p.finished && p.total > 0 {
				p.spinIdx = (p.spinIdx + 1) % len(spinnerFrames)
				p.renderLocked()
			}
			p.mu.Unlock()
		}
	}
}

func (p *ProgressBar) renderLocked() {
	filled := computeFilledWidth(p.current, p.total, progressBarWidth)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", progressBarWidth-filled)
	frame := Colorize(Task, spinnerFrames[p.spinIdx%len(spinnerFrames)], ShouldUseColor(p.out))
	elapsed := time.Since(p.startedAt).Seconds()
	writef(p.out, "\r\033[2K%s [%s] %d/%d  %s (%.1fs)", frame, bar, p.current, p.total, p.label, elapsed)
}

func computeFilledWidth(current, total, width int) int {
	if total <= 0 || current <= 0 || width <= 0 {
		return 0
	}
	if current >= total {
		return width
	}
	return (current * width) / total
}
