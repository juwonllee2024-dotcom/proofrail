package scanner

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func RunCLI(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		writeUsage(stderr)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		_, err := fmt.Fprintf(stdout, "proofrail %s\n", ToolVersion)
		return err
	}
	if args[0] != "inspect" {
		writeUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}

	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	repo := flags.String("repo", ".", "repository directory")
	base := flags.String("base", "HEAD", "Git base revision; ignored for non-Git directories")
	format := flags.String("format", "text", "output format: text, markdown, json, or sarif")
	output := flags.String("output", "-", "output file, or - for stdout")
	failOn := flags.String("fail-on", "high", "exit 1 at this severity: none, low, medium, high, or critical")
	maxFileBytes := flags.Int64("max-file-bytes", 1<<20, "maximum file size to inspect")
	all := flags.Bool("all", false, "scan all tracked and untracked files instead of only the change set")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() > 0 && *repo == "." {
		*repo = flags.Arg(0)
	}
	threshold, err := ParseSeverity(*failOn)
	if err != nil {
		return err
	}
	report, err := Scan(*repo, Options{
		Repo:         *repo,
		Base:         *base,
		All:          *all,
		Format:       *format,
		Output:       *output,
		FailOn:       threshold,
		MaxFileBytes: *maxFileBytes,
	})
	if err != nil {
		return err
	}
	data, err := Render(report, *format)
	if err != nil {
		return err
	}
	if *output == "-" || *output == "" {
		if _, err := stdout.Write(data); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(*output, data, 0o600); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
		fmt.Fprintf(stderr, "Report written to %s\n", *output)
	}
	if report.HasSeverityAtLeast(threshold) {
		return &ExitError{Code: 1, Err: fmt.Errorf("findings meet or exceed --fail-on %s", threshold)}
	}
	return nil
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "Proofrail: local evidence for changed code")
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  proofrail inspect [repository] [flags]")
	fmt.Fprintln(output, "  proofrail version")
}
