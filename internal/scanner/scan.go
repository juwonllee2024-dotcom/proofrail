package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	awsAccessKeyPattern       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubTokenPattern        = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`)
	genericSecretPattern      = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password|private[_-]?key)\b\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{12,}`)
	promptInjectionPattern    = regexp.MustCompile(`(?i)\b(?:ignore (?:all|any|the|previous) instructions|system message|reveal (?:the )?secret|disable security)\b`)                                                                // proofrail:ignore input.instruction-like-text
	dangerousCommandPattern   = regexp.MustCompile(`(?i)(?:rm\s+-rf\s+/(?:\s|$)|remove-item\b[^\r\n]*-recurse|git\s+push\b[^\r\n]*--force|curl\b[^\r\n|]+\|\s*(?:sh|bash)|powershell(?:\.exe)?\b[^\r\n]*-(?:enc|encodedcommand)\b)`) // proofrail:ignore execution.dangerous-command
	workflowWritePattern      = regexp.MustCompile(`(?i)^\s*(?:contents|pull-requests|issues|id-token)\s*:\s*write\s*$`)
	workflowWriteAllPattern   = regexp.MustCompile(`(?i)\bpermissions\s*:\s*write-all\b`)
	placeholderVersionPattern = regexp.MustCompile(`(?i)"[^"]+"\s*:\s*"(?:(?:0\.0\.0(?:-[^"]+)?)|(?:999(?:\.\d+){0,2})|[^"]*-not-real)"`)
	exactVersionPattern       = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	suppressionPattern        = regexp.MustCompile(`(?i)proofrail:ignore\s+([a-z0-9._-]+|all)`)
)

type scannedFile struct {
	record  FileRecord
	content []byte
}

func Scan(repo string, options Options) (Report, error) {
	root, err := repositoryRoot(repo)
	if err != nil {
		return Report{}, err
	}
	if options.MaxFileBytes <= 0 {
		options.MaxFileBytes = 1 << 20
	}
	if options.Base == "" {
		options.Base = "HEAD"
	}

	paths, scope, err := discoverFiles(root, options.Base, options.All)
	if err != nil {
		return Report{}, err
	}

	files, contents, err := loadFiles(root, paths, options.MaxFileBytes)
	if err != nil {
		return Report{}, err
	}

	findings := make([]Finding, 0)
	suppressions := make([]Suppression, 0)
	for _, file := range files {
		if !file.record.Scanned {
			continue
		}
		fileFindings, fileSuppressions := scanFile(file.record.Path, file.content)
		findings = append(findings, fileFindings...)
		suppressions = append(suppressions, fileSuppressions...)
	}
	findings = append(findings, scanPackageConsistency(contents)...)
	findings = append(findings, scanForMissingTests(files)...)
	sortFindings(findings)
	sortSuppressions(suppressions)

	report := Report{
		SchemaVersion: SchemaVersion,
		Tool: ToolInfo{
			Name:    "proofrail",
			Version: ToolVersion,
		},
		Scope:      scope,
		Files:      records(files),
		Findings:   findings,
		Suppressed: suppressions,
	}
	report.Summary = summarize(report.Files, report.Findings, len(report.Suppressed))
	return report, nil
}

func repositoryRoot(repo string) (string, error) {
	if repo == "" {
		repo = "."
	}
	root, err := filepath.Abs(repo)
	if err != nil {
		return "", fmt.Errorf("resolve repository: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("stat repository: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repository path is not a directory: %s", repo)
	}
	return root, nil
}

func discoverFiles(root, base string, all bool) (map[string]string, string, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		paths := make(map[string]string)
		if all {
			output, err := runGit(root, "ls-files", "-z")
			if err != nil {
				return nil, "", fmt.Errorf("list tracked files: %w", err)
			}
			for _, path := range splitNUL(output) {
				if safeGitPath(path) {
					paths[path] = "tracked"
				}
			}
		} else if resolvedBase, ok := resolveRevision(root, base); ok {
			output, err := runGit(root, "diff", "--no-ext-diff", "--name-only", "--diff-filter=ACMRTUXB", "-z", resolvedBase, "--")
			if err != nil {
				return nil, "", fmt.Errorf("read Git diff from base %q: %w", base, err)
			}
			for _, path := range splitNUL(output) {
				if safeGitPath(path) {
					paths[path] = "modified"
				}
			}
		} else if base != "HEAD" {
			return nil, "", fmt.Errorf("Git base revision %q does not exist", base)
		}
		output, err := runGit(root, "status", "--porcelain=v1", "--untracked-files=all", "-z")
		if err != nil {
			return nil, "", fmt.Errorf("read Git status: %w", err)
		}
		parseStatusPaths(output, paths)
		return paths, "working-tree", nil
	}

	paths := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && ignoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, ok := safeRelativePath(root, path)
		if ok {
			paths[rel] = "directory"
		}
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("walk repository: %w", err)
	}
	return paths, "directory", nil
}

func resolveRevision(root, revision string) (string, bool) {
	output, err := runGit(root, "rev-parse", "--verify", "--end-of-options", revision)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(output)), true
}

func parseStatusPaths(output []byte, paths map[string]string) {
	parts := splitNUL(output)
	for index := 0; index < len(parts); index++ {
		record := parts[index]
		if len(record) < 3 {
			continue
		}
		status := record[:2]
		path := record[3:]
		if (status[0] == 'R' || status[1] == 'R' || status[0] == 'C' || status[1] == 'C') && index+1 < len(parts) {
			index++
			path = parts[index]
		}
		if safeGitPath(path) {
			paths[path] = statusName(status)
		}
	}
}

func statusName(status string) string {
	if strings.Contains(status, "?") {
		return "untracked"
	}
	if strings.Contains(status, "A") {
		return "added"
	}
	if strings.Contains(status, "D") {
		return "deleted"
	}
	return "modified"
}

func runGit(root string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	return command.Output()
}

func splitNUL(data []byte) []string {
	parts := bytes.Split(data, []byte{0})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			result = append(result, string(part))
		}
	}
	return result
}

func safeGitPath(path string) bool {
	normalized := filepath.ToSlash(path)
	driveAbsolute := len(normalized) >= 3 && normalized[1] == ':' && normalized[2] == '/'
	if path == "" || filepath.IsAbs(path) || strings.HasPrefix(normalized, "/") || filepath.VolumeName(path) != "" || driveAbsolute {
		return false
	}
	return safeRelativeString(normalized)
}

func safeRelativePath(root, path string) (string, bool) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), safeRelativeString(filepath.ToSlash(rel))
}

func safeRelativeString(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean != ".." && !strings.HasPrefix(clean, "../") && clean != "."
}

func ignoredDirectory(name string) bool {
	switch name {
	case ".git", ".proofrail", "node_modules", "vendor", "dist", "build", "coverage":
		return true
	default:
		return false
	}
}

func loadFiles(root string, paths map[string]string, maxBytes int64) ([]scannedFile, map[string][]byte, error) {
	keys := make([]string, 0, len(paths))
	for path := range paths {
		keys = append(keys, path)
	}
	sort.Strings(keys)

	files := make([]scannedFile, 0, len(keys))
	contents := make(map[string][]byte)
	for _, path := range keys {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		info, err := os.Lstat(fullPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				files = append(files, scannedFile{record: FileRecord{Path: path, Status: paths[path]}})
				continue
			}
			return nil, nil, fmt.Errorf("stat %s: %w", path, err)
		}
		record := FileRecord{Path: path, Status: paths[path], Size: info.Size()}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxBytes {
			files = append(files, scannedFile{record: record})
			continue
		}
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			files = append(files, scannedFile{record: record})
			continue
		}
		digest := sha256.Sum256(data)
		record.SHA256 = hex.EncodeToString(digest[:])
		record.Scanned = true
		files = append(files, scannedFile{record: record, content: data})
		contents[path] = data
	}
	return files, contents, nil
}

func scanFile(path string, data []byte) ([]Finding, []Suppression) {
	lines := strings.Split(string(data), "\n")
	findings := make([]Finding, 0)
	suppressions := make([]Suppression, 0)
	seen := make(map[string]bool)
	suppressed := make(map[string]bool)
	isWorkflow := isWorkflowPath(path)
	isPackageFile := isPackagePath(path)
	for index, line := range lines {
		lineNumber := index + 1
		isSuppressed := func(rule string) bool {
			for _, match := range suppressionPattern.FindAllStringSubmatch(line, -1) {
				if match[1] != "all" && match[1] != rule {
					continue
				}
				key := fmt.Sprintf("%s:%d", rule, lineNumber)
				if !suppressed[key] {
					suppressed[key] = true
					suppressions = append(suppressions, Suppression{RuleID: rule, Path: path, Line: lineNumber})
				}
				return true
			}
			return false
		}
		add := func(rule string, severity Severity, message, remediation, evidence string) {
			if isSuppressed(rule) {
				return
			}
			key := fmt.Sprintf("%s:%d", rule, lineNumber)
			if seen[key] {
				return
			}
			seen[key] = true
			findings = append(findings, Finding{
				RuleID:      rule,
				Severity:    severity,
				Path:        path,
				Line:        lineNumber,
				Message:     message,
				Evidence:    evidence,
				Remediation: remediation,
			})
		}

		if awsAccessKeyPattern.MatchString(line) || githubTokenPattern.MatchString(line) || genericSecretPattern.MatchString(line) {
			add("secrets.candidate", SeverityHigh, "A secret-like value appears in the changed content.", "Remove the value, rotate it if it was real, and use a secret manager.", "matched value redacted")
		}
		if promptInjectionPattern.MatchString(line) {
			add("input.instruction-like-text", SeverityMedium, "Instruction-like text appears in repository content and must be treated as untrusted data.", "Review the text as data; do not let repository content override operator or tool policy.", "matched text redacted")
		}
		if dangerousCommandPattern.MatchString(line) {
			add("execution.dangerous-command", SeverityHigh, "A command pattern can delete data, force-update history, or pipe downloaded content into an interpreter.", "Require explicit review and use pinned, verified inputs instead of implicit shell execution.", "matched command redacted")
		}
		if isWorkflow && (workflowWritePattern.MatchString(line) || workflowWriteAllPattern.MatchString(line)) {
			add("workflow.write-permission", SeverityHigh, "A workflow grants write-capable permissions.", "Use the narrowest read-only permissions and grant write access only to an isolated, reviewed job.", "permission value recorded without repository content")
		}
		if isPackageFile && placeholderVersionPattern.MatchString(line) {
			add("dependency.placeholder-version", SeverityMedium, "A dependency version looks like a placeholder or test sentinel.", "Verify the version against its registry and lock the intended dependency graph.", "version value redacted")
		}
	}

	base := strings.ToLower(filepath.Base(filepath.FromSlash(path)))
	if sensitiveFilename(base) {
		findings = append(findings, Finding{
			RuleID:      "secrets.sensitive-file",
			Severity:    SeverityMedium,
			Path:        path,
			Message:     "A sensitive configuration file is part of the changed content.",
			Evidence:    "file name only",
			Remediation: "Keep local secret files out of version control and provide a safe example file.",
		})
	}
	return findings, suppressions
}

func scanPackageConsistency(contents map[string][]byte) []Finding {
	manifests := make(map[string]string)
	locks := make(map[string]string)
	for path := range contents {
		normalized := strings.ToLower(filepath.ToSlash(path))
		directory := filepath.ToSlash(filepath.Dir(normalized))
		switch filepath.Base(normalized) {
		case "package.json":
			manifests[directory] = path
		case "package-lock.json":
			locks[directory] = path
		}
	}
	directories := make([]string, 0, len(manifests))
	for directory := range manifests {
		if _, ok := locks[directory]; ok {
			directories = append(directories, directory)
		}
	}
	sort.Strings(directories)
	findings := make([]Finding, 0)
	for _, directory := range directories {
		findings = append(findings, scanPackagePair(contents, manifests[directory], locks[directory])...)
	}
	return findings
}

func scanPackagePair(contents map[string][]byte, packagePath, lockPath string) []Finding {
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(contents[packagePath], &manifest); err != nil {
		return []Finding{{
			RuleID:      "config.invalid-json",
			Severity:    SeverityHigh,
			Path:        packagePath,
			Message:     "package.json is not valid JSON.",
			Evidence:    "parser error redacted",
			Remediation: "Fix the manifest before running package-manager commands.",
		}}
	}
	var lock map[string]any
	if err := json.Unmarshal(contents[lockPath], &lock); err != nil {
		return []Finding{{
			RuleID:      "config.invalid-json",
			Severity:    SeverityHigh,
			Path:        lockPath,
			Message:     "package-lock.json is not valid JSON.",
			Evidence:    "parser error redacted",
			Remediation: "Regenerate the lockfile with the intended package-manager version.",
		}}
	}

	lockedVersions := make(map[string]string)
	if packages, ok := lock["packages"].(map[string]any); ok {
		for name, raw := range packages {
			if name == "" || name == "." {
				continue
			}
			packageName := strings.TrimPrefix(name, "node_modules/")
			if entry, ok := raw.(map[string]any); ok {
				if version, ok := entry["version"].(string); ok {
					lockedVersions[packageName] = version
				}
			}
		}
	}
	if dependencies, ok := lock["dependencies"].(map[string]any); ok {
		for name, raw := range dependencies {
			if entry, ok := raw.(map[string]any); ok {
				if version, ok := entry["version"].(string); ok {
					lockedVersions[name] = version
				}
			}
		}
	}

	findings := make([]Finding, 0)
	allDependencies := make(map[string]string, len(manifest.Dependencies)+len(manifest.DevDependencies))
	for name, version := range manifest.Dependencies {
		allDependencies[name] = version
	}
	for name, version := range manifest.DevDependencies {
		allDependencies[name] = version
	}
	for name, requested := range allDependencies {
		if !exactVersionPattern.MatchString(requested) {
			continue
		}
		if locked, ok := lockedVersions[name]; ok && locked != requested {
			findings = append(findings, Finding{
				RuleID:      "dependency.lockfile-drift",
				Severity:    SeverityHigh,
				Path:        packagePath,
				Line:        1,
				Message:     "A direct dependency version does not match the lockfile.",
				Evidence:    "manifest and lockfile versions redacted",
				Remediation: "Regenerate and review the lockfile with the intended dependency version.",
			})
		}
	}
	return findings
}

func scanForMissingTests(files []scannedFile) []Finding {
	hasSource := false
	hasTest := false
	firstSource := ""
	for _, file := range files {
		if !file.record.Scanned {
			continue
		}
		path := filepath.ToSlash(file.record.Path)
		if isTestPath(path) {
			hasTest = true
		}
		if isSourcePath(path) {
			hasSource = true
			if firstSource == "" {
				firstSource = path
			}
		}
	}
	if !hasSource || hasTest {
		return nil
	}
	return []Finding{{
		RuleID:      "verification.no-test-file",
		Severity:    SeverityLow,
		Path:        firstSource,
		Message:     "Source content changed but no test file was found in the scanned change set.",
		Evidence:    "file inventory only",
		Remediation: "Add or run focused tests, or document why tests are not applicable.",
	}}
}

func isWorkflowPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	workflowPath := strings.HasPrefix(normalized, ".github/workflows/") || strings.Contains(normalized, "/.github/workflows/")
	return workflowPath && (strings.HasSuffix(normalized, ".yml") || strings.HasSuffix(normalized, ".yaml"))
}

func isPackagePath(path string) bool {
	base := strings.ToLower(filepath.Base(filepath.FromSlash(path)))
	return base == "package.json" || base == "package-lock.json"
}

func sensitiveFilename(base string) bool {
	if base == ".env" || base == ".npmrc" || base == ".pypirc" || base == ".netrc" {
		return true
	}
	return strings.HasPrefix(base, ".env.") && base != ".env.example"
}

func isSourcePath(path string) bool {
	extension := strings.ToLower(filepath.Ext(filepath.FromSlash(path)))
	switch extension {
	case ".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

func isTestPath(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(filepath.FromSlash(path)))
	return strings.Contains(normalized, "/test/") || strings.Contains(normalized, "/tests/") || strings.Contains(normalized, "/__tests__/") || strings.Contains(normalized, "/spec/") || strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}

func records(files []scannedFile) []FileRecord {
	result := make([]FileRecord, 0, len(files))
	for _, file := range files {
		result = append(result, file.record)
	}
	return result
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Severity.Rank() > findings[j].Severity.Rank()
	})
}

func sortSuppressions(suppressions []Suppression) {
	sort.Slice(suppressions, func(i, j int) bool {
		if suppressions[i].Path != suppressions[j].Path {
			return suppressions[i].Path < suppressions[j].Path
		}
		if suppressions[i].Line != suppressions[j].Line {
			return suppressions[i].Line < suppressions[j].Line
		}
		return suppressions[i].RuleID < suppressions[j].RuleID
	})
}

func summarize(files []FileRecord, findings []Finding, suppressed int) Summary {
	summary := Summary{Files: len(files), Findings: len(findings), Suppressed: suppressed}
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityLow:
			summary.Low++
		case SeverityMedium:
			summary.Medium++
		case SeverityHigh:
			summary.High++
		case SeverityCritical:
			summary.Critical++
		}
	}
	return summary
}
