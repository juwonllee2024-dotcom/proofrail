package scanner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func Render(report Report, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return renderJSON(report)
	case "sarif":
		return renderSARIF(report)
	case "markdown", "md":
		return []byte(renderMarkdown(report)), nil
	case "text", "terminal", "":
		return []byte(renderText(report)), nil
	default:
		return nil, fmt.Errorf("unsupported format %q (expected text, markdown, json, or sarif)", format)
	}
}

func renderJSON(report Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func renderText(report Report) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Proofrail %s\n", report.Tool.Version)
	fmt.Fprintf(&output, "Scope: %s\n", report.Scope)
	fmt.Fprintf(&output, "Files: %d  Findings: %d  High: %d  Medium: %d  Low: %d  Suppressed: %d\n", report.Summary.Files, report.Summary.Findings, report.Summary.High+report.Summary.Critical, report.Summary.Medium, report.Summary.Low, report.Summary.Suppressed)
	if report.Summary.Checks > 0 {
		fmt.Fprintf(&output, "Checks: %d  Passed: %d  Failed: %d  Skipped: %d\n", report.Summary.Checks, report.Summary.Passed, report.Summary.Failed, report.Summary.Skipped)
	}
	if len(report.Findings) == 0 {
		output.WriteString("No findings.\n")
		writeTextChecks(&output, report.Checks)
		return output.String()
	}
	output.WriteString("\nFindings:\n")
	for _, finding := range report.Findings {
		location := finding.Path
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, finding.Line)
		}
		fmt.Fprintf(&output, "[%s] %s %s\n", strings.ToUpper(string(finding.Severity)), finding.RuleID, location)
		fmt.Fprintf(&output, "  %s\n", finding.Message)
		fmt.Fprintf(&output, "  Fix: %s\n", finding.Remediation)
		if finding.Evidence != "" {
			fmt.Fprintf(&output, "  Evidence: %s\n", finding.Evidence)
		}
	}
	writeTextChecks(&output, report.Checks)
	return output.String()
}

func writeTextChecks(output *strings.Builder, checks []CheckResult) {
	if len(checks) == 0 {
		return
	}
	output.WriteString("\nVerification checks:\n")
	for _, check := range checks {
		fmt.Fprintf(output, "[%s] %s (%dms)\n", strings.ToUpper(check.Status), check.ID, check.DurationMS)
		if check.Error != "" {
			fmt.Fprintf(output, "  %s\n", check.Error)
		}
		if check.Stdout != "" {
			fmt.Fprintf(output, "  stdout: %s\n", strings.ReplaceAll(check.Stdout, "\n", "\\n"))
		}
		if check.Stderr != "" {
			fmt.Fprintf(output, "  stderr: %s\n", strings.ReplaceAll(check.Stderr, "\n", "\\n"))
		}
	}
}

func renderMarkdown(report Report) string {
	var output strings.Builder
	output.WriteString("# Proofrail Report\n\n")
	fmt.Fprintf(&output, "- Tool: `%s %s`\n", report.Tool.Name, report.Tool.Version)
	fmt.Fprintf(&output, "- Scope: `%s`\n", report.Scope)
	fmt.Fprintf(&output, "- Files scanned: `%d`\n", report.Summary.Files)
	fmt.Fprintf(&output, "- Findings: `%d`\n", report.Summary.Findings)
	fmt.Fprintf(&output, "- High or critical: `%d`\n", report.Summary.High+report.Summary.Critical)
	fmt.Fprintf(&output, "- Suppressed by inline directive: `%d`\n", report.Summary.Suppressed)
	if report.Summary.Checks > 0 {
		fmt.Fprintf(&output, "- Verification checks: `%d` (`%d` passed, `%d` failed, `%d` skipped)\n", report.Summary.Checks, report.Summary.Passed, report.Summary.Failed, report.Summary.Skipped)
	}

	output.WriteString("\n## Files\n\n| Path | Status | Size | Scanned |\n| --- | --- | ---: | :---: |\n")
	for _, file := range report.Files {
		fmt.Fprintf(&output, "| `%s` | %s | %d | %t |\n", markdownTable(file.Path), file.Status, file.Size, file.Scanned)
	}

	output.WriteString("\n## Findings\n")
	if len(report.Findings) == 0 {
		output.WriteString("\nNo findings.\n")
		writeMarkdownChecks(&output, report.Checks)
		return output.String()
	}
	for _, finding := range report.Findings {
		output.WriteString("\n### ")
		output.WriteString(strings.ToUpper(string(finding.Severity)))
		output.WriteString(" - ")
		output.WriteString(finding.RuleID)
		output.WriteString("\n\n")
		fmt.Fprintf(&output, "**Location:** `%s:%d`\n\n", markdownCode(finding.Path), finding.Line)
		fmt.Fprintf(&output, "**Message:** %s\n\n", finding.Message)
		fmt.Fprintf(&output, "**Remediation:** %s\n\n", finding.Remediation)
		if finding.Evidence != "" {
			fmt.Fprintf(&output, "**Evidence:** %s\n", finding.Evidence)
		}
	}
	writeMarkdownChecks(&output, report.Checks)
	return output.String()
}

func writeMarkdownChecks(output *strings.Builder, checks []CheckResult) {
	if len(checks) == 0 {
		return
	}
	output.WriteString("\n## Verification Checks\n\n| ID | Status | Duration |\n| --- | --- | ---: |\n")
	for _, check := range checks {
		fmt.Fprintf(output, "| `%s` | %s | %dms |\n", markdownCode(check.ID), check.Status, check.DurationMS)
	}
	for _, check := range checks {
		if check.Stdout == "" && check.Stderr == "" && check.Error == "" {
			continue
		}
		fmt.Fprintf(output, "\n### `%s` details\n", markdownCode(check.ID))
		if check.Error != "" {
			fmt.Fprintf(output, "\n**Error:** %s\n", check.Error)
		}
		if check.Stdout != "" {
			fmt.Fprintf(output, "\n**stdout:**\n\n```text\n%s\n```\n", markdownOutput(check.Stdout))
		}
		if check.Stderr != "" {
			fmt.Fprintf(output, "\n**stderr:**\n\n```text\n%s\n```\n", markdownOutput(check.Stderr))
		}
	}
}

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	Help             sarifText `json:"help"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func renderSARIF(report Report) ([]byte, error) {
	rules := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if _, exists := rules[finding.RuleID]; !exists {
			rules[finding.RuleID] = sarifRule{
				ID:               finding.RuleID,
				ShortDescription: sarifText{Text: finding.Message},
				Help:             sarifText{Text: finding.Remediation},
			}
		}
		level := "note"
		if finding.Severity == SeverityMedium {
			level = "warning"
		}
		if finding.Severity == SeverityHigh || finding.Severity == SeverityCritical {
			level = "error"
		}
		location := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: finding.Path},
		}}
		if finding.Line > 0 {
			location.PhysicalLocation.Region = &sarifRegion{StartLine: finding.Line}
		}
		results = append(results, sarifResult{
			RuleID:    finding.RuleID,
			Level:     level,
			Message:   sarifText{Text: finding.Message},
			Locations: []sarifLocation{location},
		})
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	data, err := json.MarshalIndent(sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           report.Tool.Name,
				Version:        report.Tool.Version,
				InformationURI: "https://github.com/proofrail/proofrail",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func markdownTable(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "|", "\\|")
}

func markdownCode(value string) string {
	return strings.ReplaceAll(value, "`", "'")
}

func markdownOutput(value string) string {
	return strings.ReplaceAll(value, "```", "` ` `")
}
