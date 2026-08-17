package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultVerifyConfig = ".proofrail.yml"
	maxConfigBytes      = 64 << 10
	maxCheckCount       = 32
	maxCheckArgs        = 64
	maxCheckArgBytes    = 4 << 10
	defaultCheckTimeout = 120 * time.Second
	maxCheckTimeout     = 30 * time.Minute
	maxCheckOutput      = 16 << 10
	maxCopyBytes        = 512 << 20
)

var (
	checkIDPattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	commandSecretPattern = regexp.MustCompile(`(?i)\b(?:token|password|secret|api[_-]?key|private[_-]?key)\b\s*[:=]\s*["']?[^\s"']+`)
)

func Verify(repo string, options Options, configPath string, run, trustConfig bool) (Report, error) {
	root, err := repositoryRoot(repo)
	if err != nil {
		return Report{}, err
	}
	report, err := Scan(root, options)
	if err != nil {
		return Report{}, err
	}

	config, err := loadVerifyConfig(root, configPath)
	if err != nil {
		return Report{}, err
	}
	report.Checks = make([]CheckResult, 0, len(config.Checks))
	if !run {
		for _, check := range config.Checks {
			report.Checks = append(report.Checks, CheckResult{
				ID:      check.ID,
				Command: redactedCommand(check),
				Status:  "skipped",
				Error:   "execution disabled; pass both --run and --trust-config to execute",
			})
		}
		report.Summary = summarizeWithChecks(report.Files, report.Findings, len(report.Suppressed), report.Checks)
		return report, nil
	}
	if !trustConfig {
		return Report{}, errors.New("refusing to execute verification commands without --trust-config")
	}

	workRoot, err := os.MkdirTemp("", "proofrail-verify-")
	if err != nil {
		return Report{}, fmt.Errorf("create verification workspace: %w", err)
	}
	defer os.RemoveAll(workRoot)
	if err := copyRepository(root, workRoot); err != nil {
		return Report{}, fmt.Errorf("prepare verification workspace: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(workRoot, ".proofrail-tmp"), 0o700); err != nil {
		return Report{}, fmt.Errorf("create verification temp directory: %w", err)
	}

	for _, check := range config.Checks {
		report.Checks = append(report.Checks, runCheck(workRoot, check))
	}
	report.Summary = summarizeWithChecks(report.Files, report.Findings, len(report.Suppressed), report.Checks)
	return report, nil
}

func loadVerifyConfig(root, configPath string) (VerifyConfig, error) {
	if configPath == "" {
		configPath = defaultVerifyConfig
	}
	if !safeConfigPath(configPath) {
		return VerifyConfig{}, fmt.Errorf("verification config path must stay within the repository: %q", configPath)
	}
	if !safeConfigTarget(root, configPath) {
		return VerifyConfig{}, fmt.Errorf("verification config path traverses a symlink or non-directory: %q", configPath)
	}
	path := filepath.Join(root, filepath.FromSlash(configPath))
	info, err := os.Lstat(path)
	if err != nil {
		return VerifyConfig{}, fmt.Errorf("read verification config %q: %w", configPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return VerifyConfig{}, fmt.Errorf("verification config is not a regular file: %q", configPath)
	}
	if info.Size() > maxConfigBytes {
		return VerifyConfig{}, fmt.Errorf("verification config exceeds %d bytes", maxConfigBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return VerifyConfig{}, fmt.Errorf("read verification config %q: %w", configPath, err)
	}
	var config VerifyConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return VerifyConfig{}, fmt.Errorf("parse verification config %q: %w", configPath, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return VerifyConfig{}, fmt.Errorf("parse verification config %q: multiple YAML documents are not allowed", configPath)
		}
		return VerifyConfig{}, fmt.Errorf("parse verification config %q: %w", configPath, err)
	}
	if config.Version != 1 {
		return VerifyConfig{}, fmt.Errorf("unsupported verification config version %d (expected 1)", config.Version)
	}
	if len(config.Checks) == 0 {
		return VerifyConfig{}, errors.New("verification config must define at least one check")
	}
	if len(config.Checks) > maxCheckCount {
		return VerifyConfig{}, fmt.Errorf("verification config defines more than %d checks", maxCheckCount)
	}
	seen := make(map[string]bool, len(config.Checks))
	for index := range config.Checks {
		check := &config.Checks[index]
		check.Program = strings.TrimSpace(check.Program)
		if !checkIDPattern.MatchString(check.ID) {
			return VerifyConfig{}, fmt.Errorf("check %d has invalid id %q", index+1, check.ID)
		}
		if seen[check.ID] {
			return VerifyConfig{}, fmt.Errorf("verification check id %q is duplicated", check.ID)
		}
		seen[check.ID] = true
		if check.Program == "" || strings.ContainsRune(check.Program, '\x00') {
			return VerifyConfig{}, fmt.Errorf("check %q has an invalid program", check.ID)
		}
		if len(check.Args) > maxCheckArgs {
			return VerifyConfig{}, fmt.Errorf("check %q has more than %d arguments", check.ID, maxCheckArgs)
		}
		for _, arg := range check.Args {
			if len(arg) > maxCheckArgBytes || strings.ContainsRune(arg, '\x00') {
				return VerifyConfig{}, fmt.Errorf("check %q has an invalid argument", check.ID)
			}
		}
		if check.TimeoutSeconds == 0 {
			check.TimeoutSeconds = int(defaultCheckTimeout / time.Second)
		}
		if check.TimeoutSeconds < 1 || time.Duration(check.TimeoutSeconds)*time.Second > maxCheckTimeout {
			return VerifyConfig{}, fmt.Errorf("check %q timeout must be between 1 and %d seconds", check.ID, int(maxCheckTimeout/time.Second))
		}
	}
	return config, nil
}

func safeConfigPath(path string) bool {
	normalized := filepath.ToSlash(path)
	driveAbsolute := len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/'
	return path != "" && !filepath.IsAbs(path) && !strings.HasPrefix(normalized, "/") && filepath.VolumeName(path) == "" && !driveAbsolute && safeRelativeString(normalized)
}

func safeConfigTarget(root, relative string) bool {
	current := root
	parts := strings.Split(filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative))), "/")
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			return errors.Is(err, os.ErrNotExist)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if index < len(parts)-1 && !info.IsDir() {
			return false
		}
	}
	return true
}

func copyRepository(source, destination string) error {
	var copied int64
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, ok := safeRelativePath(source, path)
		if path != source && !ok {
			return nil
		}
		if entry.IsDir() {
			if path != source && executionIgnoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			if path != source {
				return os.MkdirAll(filepath.Join(destination, filepath.FromSlash(rel)), 0o755)
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || copied > maxCopyBytes-info.Size() {
			return fmt.Errorf("repository copy exceeds %d bytes", maxCopyBytes)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(destination, filepath.FromSlash(rel))), 0o755); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(filepath.Join(destination, filepath.FromSlash(rel)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			input.Close()
			return err
		}
		remaining := maxCopyBytes - copied
		written, copyErr := io.Copy(output, io.LimitReader(input, remaining+1))
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if closeInputErr != nil {
			return closeInputErr
		}
		if written > remaining {
			return fmt.Errorf("repository copy exceeds %d bytes", maxCopyBytes)
		}
		copied += written
		return nil
	})
}

func executionIgnoredDirectory(name string) bool {
	switch name {
	case ".git", ".proofrail":
		return true
	default:
		return false
	}
}

func runCheck(workRoot string, check CheckConfig) CheckResult {
	result := CheckResult{ID: check.ID, Command: redactedCommand(check)}
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(check.TimeoutSeconds)*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, check.Program, check.Args...)
	command.Dir = workRoot
	command.Env = sanitizedEnvironment(workRoot)
	var stdout, stderr cappedBuffer
	stdout.limit = maxCheckOutput
	stderr.limit = maxCheckOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result.DurationMS = time.Since(start).Milliseconds()
	result.Stdout = redactCheckOutput(stdout.String(), workRoot)
	result.Stderr = redactCheckOutput(stderr.String(), workRoot)

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Status = "timed_out"
		result.Error = fmt.Sprintf("command timed out after %d seconds", check.TimeoutSeconds)
		return result
	}
	if err == nil {
		result.Status = "passed"
		return result
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.Status = "failed"
		result.ExitCode = exitErr.ExitCode()
		result.Error = fmt.Sprintf("command exited with status %d", result.ExitCode)
		return result
	}
	result.Status = "error"
	result.Error = "command could not be started"
	return result
}

func sanitizedEnvironment(workRoot string) []string {
	allowed := map[string]bool{
		"COMSPEC":     true,
		"PATH":        true,
		"PATHEXT":     true,
		"SYSTEMDRIVE": true,
		"SYSTEMROOT":  true,
	}
	environment := make([]string, 0, len(allowed)+10)
	for _, value := range os.Environ() {
		name, _, ok := strings.Cut(value, "=")
		if ok && allowed[strings.ToUpper(name)] {
			environment = append(environment, value)
		}
	}
	tempRoot := filepath.Join(workRoot, ".proofrail-tmp")
	environment = append(environment,
		"HOME="+workRoot,
		"USERPROFILE="+workRoot,
		"TEMP="+tempRoot,
		"TMP="+tempRoot,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
	)
	return environment
}

func redactedCommand(check CheckConfig) []string {
	command := make([]string, 0, len(check.Args)+1)
	program := check.Program
	if filepath.IsAbs(program) || filepath.VolumeName(program) != "" {
		program = filepath.Base(filepath.FromSlash(program))
	}
	command = append(command, program)
	command = append(command, check.Args...)
	for index := range command {
		command[index] = redactText(command[index])
	}
	return command
}

func redactCheckOutput(value, workRoot string) string {
	value = strings.ReplaceAll(value, workRoot, "<verification-root>")
	return redactText(value)
}

func redactText(value string) string {
	value = awsAccessKeyPattern.ReplaceAllString(value, "[REDACTED]")
	value = githubTokenPattern.ReplaceAllString(value, "[REDACTED]")
	value = genericSecretPattern.ReplaceAllString(value, "[REDACTED]")
	return commandSecretPattern.ReplaceAllString(value, "[REDACTED]")
}

type cappedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	if b.limit <= 0 {
		return len(data), nil
	}
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.Buffer.Write(data[:remaining])
		b.truncated = true
		return len(data), nil
	}
	return b.Buffer.Write(data)
}

func (b *cappedBuffer) String() string {
	value := b.Buffer.String()
	if b.truncated {
		value += "\n[output truncated]"
	}
	return value
}

func summarizeWithChecks(files []FileRecord, findings []Finding, suppressed int, checks []CheckResult) Summary {
	summary := summarize(files, findings, suppressed)
	summary.Checks = len(checks)
	for _, check := range checks {
		switch check.Status {
		case "passed":
			summary.Passed++
		case "failed", "timed_out", "error":
			summary.Failed++
		case "skipped":
			summary.Skipped++
		}
	}
	return summary
}
