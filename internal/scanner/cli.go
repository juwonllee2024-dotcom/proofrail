package scanner

import (
	"flag"
	"fmt"
	"io"
	"os"
)

type cliFlags struct {
	repo         string
	base         string
	format       string
	output       string
	failOn       string
	maxFileBytes int64
	all          bool
	config       string
	run          bool
	trustConfig  bool
}

func RunCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		writeUsage(stderr)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		_, err := fmt.Fprintf(stdout, "proofrail %s\n", ToolVersion)
		return err
	}
	switch args[0] {
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	default:
		writeUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInspect(args []string, stdout, stderr io.Writer) error {
	values, err := parseCLIFlags("inspect", args, false, stderr)
	if err != nil {
		return err
	}
	threshold, err := ParseSeverity(values.failOn)
	if err != nil {
		return err
	}
	report, err := Scan(values.repo, Options{
		Repo:         values.repo,
		Base:         values.base,
		All:          values.all,
		Format:       values.format,
		Output:       values.output,
		FailOn:       threshold,
		MaxFileBytes: values.maxFileBytes,
	})
	if err != nil {
		return err
	}
	if err := writeReport(report, values.format, values.output, stdout, stderr); err != nil {
		return err
	}
	return reportFailure(report, threshold, false)
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	values, err := parseCLIFlags("verify", args, true, stderr)
	if err != nil {
		return err
	}
	threshold, err := ParseSeverity(values.failOn)
	if err != nil {
		return err
	}
	report, err := Verify(values.repo, Options{
		Repo:         values.repo,
		Base:         values.base,
		All:          values.all,
		Format:       values.format,
		Output:       values.output,
		FailOn:       threshold,
		MaxFileBytes: values.maxFileBytes,
	}, values.config, values.run, values.trustConfig)
	if err != nil {
		return err
	}
	if err := writeReport(report, values.format, values.output, stdout, stderr); err != nil {
		return err
	}
	return reportFailure(report, threshold, true)
}

func parseCLIFlags(command string, args []string, verification bool, stderr io.Writer) (cliFlags, error) {
	values := cliFlags{repo: ".", base: "HEAD", format: "text", output: "-", failOn: "high", maxFileBytes: 1 << 20}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&values.repo, "repo", values.repo, "repository directory")
	flags.StringVar(&values.base, "base", values.base, "Git base revision; ignored for non-Git directories")
	flags.StringVar(&values.format, "format", values.format, "output format: text, markdown, json, or sarif")
	flags.StringVar(&values.output, "output", values.output, "output file, or - for stdout")
	flags.StringVar(&values.failOn, "fail-on", values.failOn, "exit 1 at this severity: none, low, medium, high, or critical")
	flags.Int64Var(&values.maxFileBytes, "max-file-bytes", values.maxFileBytes, "maximum file size to inspect")
	flags.BoolVar(&values.all, "all", false, "scan all tracked and untracked files instead of only the change set")
	if verification {
		flags.StringVar(&values.config, "config", defaultVerifyConfig, "verification YAML file relative to the repository")
		flags.BoolVar(&values.run, "run", false, "execute configured verification commands")
		flags.BoolVar(&values.trustConfig, "trust-config", false, "explicitly allow configured commands to execute")
	}
	if err := flags.Parse(args); err != nil {
		return cliFlags{}, err
	}
	if flags.NArg() > 0 && values.repo == "." {
		values.repo = flags.Arg(0)
	}
	return values, nil
}

func writeReport(report Report, format, output string, stdout, stderr io.Writer) error {
	data, err := Render(report, format)
	if err != nil {
		return err
	}
	if output == "-" || output == "" {
		_, err = stdout.Write(data)
		return err
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	_, err = fmt.Fprintf(stderr, "Report written to %s\n", output)
	return err
}

func reportFailure(report Report, threshold Severity, includeChecks bool) error {
	if report.HasSeverityAtLeast(threshold) {
		return &ExitError{Code: 1, Err: fmt.Errorf("findings meet or exceed --fail-on %s", threshold)}
	}
	if includeChecks && report.HasFailedChecks() {
		return &ExitError{Code: 1, Err: errorsForChecks(report)}
	}
	return nil
}

func errorsForChecks(report Report) error {
	return fmt.Errorf("verification checks failed (%d failed)", report.Summary.Failed)
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "Proofrail: local evidence for changed code")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  proofrail inspect [repository] [flags]")
	fmt.Fprintln(output, "  proofrail verify [repository] [flags]")
	fmt.Fprintln(output, "  proofrail version")
}
