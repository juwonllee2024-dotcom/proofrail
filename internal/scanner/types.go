package scanner

import (
	"errors"
	"fmt"
)

const (
	ToolVersion   = "0.1.0-spike"
	SchemaVersion = "0.2"
)

type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func ParseSeverity(value string) (Severity, error) {
	severity := Severity(value)
	switch severity {
	case SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return severity, nil
	default:
		return SeverityNone, fmt.Errorf("invalid severity %q (expected none, low, medium, high, or critical)", value)
	}
}

type Options struct {
	Repo         string
	Base         string
	All          bool
	Format       string
	Output       string
	FailOn       Severity
	MaxFileBytes int64
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          ToolInfo      `json:"tool"`
	Scope         string        `json:"scope"`
	Files         []FileRecord  `json:"files"`
	Findings      []Finding     `json:"findings"`
	Suppressed    []Suppression `json:"suppressed"`
	Checks        []CheckResult `json:"checks"`
	Summary       Summary       `json:"summary"`
}

type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type FileRecord struct {
	Path    string `json:"path"`
	Status  string `json:"status"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Scanned bool   `json:"scanned"`
}

type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"severity"`
	Path        string   `json:"path"`
	Line        int      `json:"line,omitempty"`
	Message     string   `json:"message"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
}

type Suppression struct {
	RuleID string `json:"rule_id"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
}

type CheckConfig struct {
	ID             string   `yaml:"id" json:"id"`
	Program        string   `yaml:"program" json:"program"`
	Args           []string `yaml:"args" json:"args"`
	TimeoutSeconds int      `yaml:"timeout_seconds" json:"timeout_seconds"`
}

type VerifyConfig struct {
	Version int           `yaml:"version" json:"version"`
	Checks  []CheckConfig `yaml:"checks" json:"checks"`
}

type CheckResult struct {
	ID         string   `json:"id"`
	Command    []string `json:"command"`
	Status     string   `json:"status"`
	ExitCode   int      `json:"exit_code,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type Summary struct {
	Files      int `json:"files"`
	Findings   int `json:"findings"`
	Low        int `json:"low"`
	Medium     int `json:"medium"`
	High       int `json:"high"`
	Critical   int `json:"critical"`
	Suppressed int `json:"suppressed"`
	Checks     int `json:"checks"`
	Passed     int `json:"checks_passed"`
	Failed     int `json:"checks_failed"`
	Skipped    int `json:"checks_skipped"`
}

func (r Report) HasSeverityAtLeast(threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	for _, finding := range r.Findings {
		if finding.Severity.Rank() >= threshold.Rank() {
			return true
		}
	}
	return false
}

func (r Report) HasFailedChecks() bool {
	for _, check := range r.Checks {
		if check.Status == "failed" || check.Status == "timed_out" || check.Status == "error" {
			return true
		}
	}
	return false
}

type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func ExitCode(err error) int {
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return 1
}
