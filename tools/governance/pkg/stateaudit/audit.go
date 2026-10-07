package stateaudit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// IgnoreFileName is the ignore file below the Terraform directory.
const IgnoreFileName = ".tfstate-audit-ignore.yaml"

// ErrCredentialsMissing reports empty TF_HTTP_USERNAME or TF_HTTP_PASSWORD.
var ErrCredentialsMissing = errors.New("stateaudit: TF_HTTP_USERNAME and TF_HTTP_PASSWORD are empty, export the state backend credentials first")

// ErrRevealRefused reports --reveal outside an interactive terminal, where a value would reach a log, a pipe, or a file.
var ErrRevealRefused = errors.New("stateaudit: --reveal prints values to an interactive terminal alone, outside CI")

// Config holds the inputs of one audit.
type Config struct {
	Layers   []Layer
	Source   StateSource
	Detector ValueDetector
	Ignores  []Ignore
	History  bool
	Reveal   bool
}

// Audit scans the current state of every layer, and every historical version with cfg.History.
func Audit(ctx context.Context, cfg Config) (Report, error) {
	var report Report
	var findings []Finding
	for _, layer := range cfg.Layers {
		found, scanned, err := auditLayer(ctx, cfg, layer)
		if errors.Is(err, ErrStateMissing) {
			continue
		}
		if err != nil {
			return Report{}, fmt.Errorf("stateaudit: layer %s: %w", layer.Name, err)
		}
		findings = append(findings, found...)
		report.Scanned = append(report.Scanned, scanned...)
	}
	report.Findings, report.UnusedIgnores = ApplyIgnores(findings, cfg.Ignores)
	return report, nil
}

func auditLayer(ctx context.Context, cfg Config, layer Layer) ([]Finding, []string, error) {
	current, err := cfg.Source.FetchCurrent(ctx, layer.Address)
	if err != nil {
		return nil, nil, err
	}
	findings, err := scanState(layer.Name, "current", current, cfg.Detector, cfg.Reveal)
	if err != nil {
		return nil, nil, err
	}
	scanned := []string{layer.Name + "@current"}
	if !cfg.History {
		return findings, scanned, nil
	}

	state, err := parseState(current)
	if err != nil {
		return nil, nil, err
	}
	for serial := state.Serial - 1; serial >= 1; serial-- {
		document, err := cfg.Source.FetchVersion(ctx, layer.Address, serial)
		if errors.Is(err, ErrVersionMissing) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		version := "serial-" + strconv.Itoa(serial)
		found, err := scanState(layer.Name, version, document, cfg.Detector, cfg.Reveal)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, found...)
		scanned = append(scanned, layer.Name+"@"+version)
	}
	return findings, scanned, nil
}

// Run audits cfg, writes the report to w, and returns ErrFindings on a finding or an unused ignore entry.
func Run(ctx context.Context, cfg Config, w io.Writer) error {
	report, err := Audit(ctx, cfg)
	if err != nil {
		return err
	}
	err = WriteReport(w, report)
	if err != nil {
		return err
	}
	if len(report.Findings) > 0 || len(report.UnusedIgnores) > 0 {
		return ErrFindings
	}
	return nil
}

// ConfigFromEnv builds the configuration of terraformDir from the TF_HTTP credentials of getenv.
func ConfigFromEnv(terraformDir string, getenv func(string) string, history bool) (Config, error) {
	username, password := getenv("TF_HTTP_USERNAME"), getenv("TF_HTTP_PASSWORD")
	if username == "" || password == "" {
		return Config{}, ErrCredentialsMissing
	}
	layers, err := DiscoverLayers(filepath.Join(terraformDir, "layers"))
	if err != nil {
		return Config{}, err
	}
	ignores, err := LoadIgnores(filepath.Join(terraformDir, IgnoreFileName))
	if err != nil {
		return Config{}, err
	}
	detector, err := NewGitleaksDetector()
	if err != nil {
		return Config{}, err
	}
	return Config{
		Layers:   layers,
		Source:   HTTPSource{Client: &http.Client{Timeout: 30 * time.Second}, Username: username, Password: password},
		Detector: detector,
		Ignores:  ignores,
		History:  history,
	}, nil
}

// NewCommand returns the subcommand state-audit.
func NewCommand(resolve func(history bool) (Config, error)) *cobra.Command {
	var history, reveal bool
	cmd := &cobra.Command{
		Use:   "state-audit",
		Short: "Report every location of a Terraform state which holds a confidential value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if reveal {
				if err := checkRevealOutput(cmd.OutOrStdout(), os.Getenv); err != nil {
					return err
				}
			}
			cfg, err := resolve(history)
			if err != nil {
				return err
			}
			cfg.Reveal = reveal
			return Run(cmd.Context(), cfg, cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&history, "history", false, "also scan every historical state version which the backend holds")
	cmd.Flags().BoolVar(&reveal, "reveal", false, "print each value below its location, on an interactive terminal outside CI alone")
	return cmd
}

// checkRevealOutput accepts an interactive terminal outside CI, where the values stay off logs, pipes, and files.
func checkRevealOutput(w io.Writer, getenv func(string) string) error {
	if getenv("CI") != "" {
		return ErrRevealRefused
	}
	file, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return ErrRevealRefused
	}
	return nil
}
