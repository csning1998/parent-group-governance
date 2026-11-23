// Package ui provides formatted log output, visual section dividers, and interactive user prompts.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/term"
)

const (
	Info Level = iota
	Step
	Task
	Warn
	Error
	Fatal
	OK
	Input
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[0;31m"
	colorGreen   = "\033[0;32m"
	colorYellow  = "\033[0;33m"
	colorCyan    = "\033[0;36m"
	colorPurple  = "\033[0;35m"
	colorBoldRed = "\033[1;31m"
	colorBlue    = "\033[1;34m"
)

var (
	isTerminalFn   = term.IsTerminal
	readPasswordFn = term.ReadPassword
)

// Level defines log output severity categories.
type Level int

// Printer writes ANSI colored log lines to standard output and standard error by log level.
type Printer struct {
	out    io.Writer
	errOut io.Writer
}

// New constructs a Printer writing normal output to out and errors to errOut.
func New(out, errOut io.Writer) *Printer {
	return &Printer{out: out, errOut: errOut}
}

// Print writes an ANSI colored log line formatted as "[LEVEL] msg".
// Error and Fatal write to standard error. All other levels write to standard output.
func (p *Printer) Print(level Level, msg string) {
	tag, color := level.label()
	dest := p.out
	if level == Error || level == Fatal {
		dest = p.errOut
	}
	writef(dest, "%s[%s] %s%s\n", color, tag, msg, colorReset)
}

// PrintDivider outputs a 60 character horizontal line using char. An empty char defaults to "-".
func (p *Printer) PrintDivider(char string) {
	if char == "" {
		char = "-"
	}
	writeln(p.out, strings.Repeat(char, 60))
}

// PromptConfirm displays msg and returns true when input is "Y" or "y".
func (p *Printer) PromptConfirm(in *bufio.Reader, msg string) bool {
	p.Print(Input, msg)
	line := readTrimmedLine(in)
	return line == "Y" || line == "y"
}

// PromptInput displays msg and returns the trimmed input line. Empty input returns def.
func (p *Printer) PromptInput(in *bufio.Reader, msg, def string) string {
	p.Print(Input, msg)
	line := readTrimmedLine(in)
	if line == "" {
		return def
	}
	return line
}

// PromptMultiSelect displays a numbered list of options and returns the chosen zero based indices.
// Tokens may be separated by commas, whitespace, or both.
// It returns ok=false when input is empty or any token is invalid or out of range.
func (p *Printer) PromptMultiSelect(in *bufio.Reader, prompt string, options []string) (indices []int, ok bool) {
	for i, opt := range options {
		writef(p.out, "%d) %s\n", i+1, opt)
	}
	p.Print(Input, prompt)
	line := readTrimmedLine(in)
	if line == "" {
		return nil, false
	}

	tokens := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(tokens) == 0 {
		return nil, false
	}

	seen := make(map[int]bool, len(tokens))
	for _, tok := range tokens {
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > len(options) {
			return nil, false
		}
		index := n - 1
		if !seen[index] {
			seen[index] = true
			indices = append(indices, index)
		}
	}
	return indices, true
}

// PromptSecret displays msg and reads a secret with terminal echo disabled when fd is a TTY.
// When fd is not a TTY, the method reads one line from the buffered reader. The printer never writes the secret.
func (p *Printer) PromptSecret(in *bufio.Reader, fd int, msg string) (string, error) {
	tag, color := Input.label()
	writef(p.out, "%s[%s] %s%s", color, tag, msg, colorReset)

	if isTerminalFn(fd) {
		secret, err := readPasswordFn(fd)
		writeln(p.out)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}

	line, err := in.ReadString('\n')
	writeln(p.out)
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

// PromptSelect displays a numbered list of options and returns the chosen zero based index.
// It returns ok=false when input is empty, nonnumeric, or out of range.
func (p *Printer) PromptSelect(in *bufio.Reader, prompt string, options []string) (index int, ok bool) {
	for i, opt := range options {
		writef(p.out, "%d) %s\n", i+1, opt)
	}
	p.Print(Input, prompt)
	line := readTrimmedLine(in)

	for _, r := range line {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(line)
	if line == "" || err != nil || n < 1 || n > len(options) {
		return 0, false
	}
	return n - 1, true
}

// Terminal output is best effort because CLI prompts cannot recover from a broken pipe.
func writef(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// Terminal output is best effort because CLI prompts cannot recover from a broken pipe.
func writeln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

// EOF and read errors yield the trimmed partial line or an empty string so callers fall back to defaults.
func readTrimmedLine(in *bufio.Reader) string {
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}

func (l Level) label() (tag, color string) {
	switch l {
	case Info:
		return "INFO", colorGreen
	case OK:
		return "OK", colorGreen
	case Step:
		return "STEP", colorBlue
	case Task:
		return "TASK", colorCyan
	case Warn:
		return "WARN", colorYellow
	case Error:
		return "ERROR", colorRed
	case Fatal:
		return "FATAL", colorBoldRed
	case Input:
		return "INPUT", colorPurple
	default:
		return "INFO", colorGreen
	}
}
