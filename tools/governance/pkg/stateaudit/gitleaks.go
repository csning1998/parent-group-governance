package stateaudit

import (
	"fmt"
	"slices"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type gitleaksDetector struct {
	detector *detect.Detector
}

// NewGitleaksDetector returns a ValueDetector of the default gitleaks rules.
func NewGitleaksDetector() (ValueDetector, error) {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("stateaudit: load the gitleaks rules: %w", err)
	}
	detector.MaxDecodeDepth = 5
	detector.Redact = 100
	return gitleaksDetector{detector: detector}, nil
}

// Detect scans "key": "value", since the generic gitleaks rules require the attribute name as context.
func (g gitleaksDetector) Detect(key, value string) []Detection {
	var detections []Detection
	for _, finding := range g.detector.DetectString(`"` + key + `": "` + value + `"`) {
		detection := Detection("gitleaks:" + finding.RuleID)
		if !slices.Contains(detections, detection) {
			detections = append(detections, detection)
		}
	}
	return detections
}
