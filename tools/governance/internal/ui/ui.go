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

// Printer writes formatted, color-coded log lines to standard output and standard error streams based on log level.
type Printer struct {
	out    io.Writer
	errOut io.Writer
}

func New(out, errOut io.Writer) *Printer {
	return &Printer{out: out, errOut: errOut}
}

// Print writes a color-coded log line formatted as "[LEVEL] msg".
// Non-error levels write to standard output. Error and Fatal levels write to standard error.
func (p *Printer) Print(level Level, msg string) {
	tag, color := level.label()
	dest := p.out
	if level == Error || level == Fatal {
		dest = p.errOut
	}
	_, _ = fmt.Fprintf(dest, "%s[%s] %s%s\n", color, tag, msg, colorReset)
}

// PrintDivider outputs a 60-character horizontal line using char. Defaults to "-" if char is empty.
func (p *Printer) PrintDivider(char string) {
	if char == "" {
		char = "-"
	}
	_, _ = fmt.Fprintln(p.out, strings.Repeat(char, 60))
}

// PromptConfirm displays msg and returns true if input matches "Y" or "y".
func (p *Printer) PromptConfirm(in *bufio.Reader, msg string) bool {
	p.Print(Input, msg)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	return line == "Y" || line == "y"
}

// PromptInput displays msg and returns whitespace-trimmed input line. Returns def if input is empty.
func (p *Printer) PromptInput(in *bufio.Reader, msg, def string) string {
	p.Print(Input, msg)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// PromptMultiSelect displays a numbered list of options and returns the zero-based indices of
// every chosen option, accepting tokens separated by commas, whitespace, or both.
// Returns ok=false if input is empty, or any token is non-numeric or out of range.
func (p *Printer) PromptMultiSelect(in *bufio.Reader, prompt string, options []string) (indices []int, ok bool) {
	for i, opt := range options {
		_, _ = fmt.Fprintf(p.out, "%d) %s\n", i+1, opt)
	}
	p.Print(Input, prompt)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
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
	_, _ = fmt.Fprintf(p.out, "%s[%s] %s%s", color, tag, msg, colorReset)

	if isTerminalFn(fd) {
		secret, err := readPasswordFn(fd)
		_, _ = fmt.Fprintln(p.out)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}

	line, err := in.ReadString('\n')
	_, _ = fmt.Fprintln(p.out)
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

// PromptSelect displays a numbered list of options and returns the zero-based index of the selected option.
// Returns ok=false if input is empty, non-numeric, or out of range.
func (p *Printer) PromptSelect(in *bufio.Reader, prompt string, options []string) (index int, ok bool) {
	for i, opt := range options {
		_, _ = fmt.Fprintf(p.out, "%d) %s\n", i+1, opt)
	}
	p.Print(Input, prompt)
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)

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

func (l Level) interactiveLabel() (tag, color string) {
	if l == Input {
		return "INPUT", colorPurple
	}
	return "", ""
}

func (l Level) label() (tag, color string) {
	if tag, color = l.severityLabel(); tag != "" {
		return tag, color
	}
	if tag, color = l.narrativeLabel(); tag != "" {
		return tag, color
	}
	if tag, color = l.interactiveLabel(); tag != "" {
		return tag, color
	}
	return "INFO", colorGreen
}

func (l Level) narrativeLabel() (tag, color string) {
	switch l {
	case Step:
		return "STEP", colorBlue
	case Task:
		return "TASK", colorCyan
	default:
		return "", ""
	}
}

func (l Level) severityLabel() (tag, color string) {
	switch l {
	case Info:
		return "INFO", colorGreen
	case Warn:
		return "WARN", colorYellow
	case Error:
		return "ERROR", colorRed
	case Fatal:
		return "FATAL", colorBoldRed
	case OK:
		return "OK", colorGreen
	default:
		return "", ""
	}
}
