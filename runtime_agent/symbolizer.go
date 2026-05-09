package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Symbol is a resolved function address.
type Symbol struct {
	Name   string
	File   string // source file (repo-relative when possible)
	Line   int
	Binary string
}

// Symbolizer resolves instruction pointers to source locations.
// It uses llvm-symbolizer (preferred) falling back to addr2line.
type Symbolizer struct {
	mu      sync.Mutex
	cache   map[symbolKey]Symbol
	binPath string // path to llvm-symbolizer or addr2line binary
	useAddr2line bool
}

type symbolKey struct {
	binary string
	ip     uint64
}

func NewSymbolizer() (*Symbolizer, error) {
	bin, err := exec.LookPath("llvm-symbolizer")
	if err != nil {
		bin, err = exec.LookPath("addr2line")
		if err != nil {
			return nil, fmt.Errorf("neither llvm-symbolizer nor addr2line found in PATH")
		}
		return &Symbolizer{cache: make(map[symbolKey]Symbol), binPath: bin, useAddr2line: true}, nil
	}
	return &Symbolizer{cache: make(map[symbolKey]Symbol), binPath: bin}, nil
}

// Resolve maps a (binary path, instruction pointer) to a Symbol.
// Results are cached forever within the agent lifetime — binaries don't change at runtime.
func (s *Symbolizer) Resolve(binaryPath string, ip uint64) (Symbol, error) {
	key := symbolKey{binary: binaryPath, ip: ip}

	s.mu.Lock()
	if sym, ok := s.cache[key]; ok {
		s.mu.Unlock()
		return sym, nil
	}
	s.mu.Unlock()

	sym, err := s.resolveUncached(binaryPath, ip)
	if err != nil {
		return Symbol{}, err
	}

	s.mu.Lock()
	s.cache[key] = sym
	s.mu.Unlock()
	return sym, nil
}

func (s *Symbolizer) resolveUncached(binaryPath string, ip uint64) (Symbol, error) {
	if s.useAddr2line {
		return s.resolveAddr2line(binaryPath, ip)
	}
	return s.resolveLLVM(binaryPath, ip)
}

func (s *Symbolizer) resolveLLVM(binaryPath string, ip uint64) (Symbol, error) {
	cmd := exec.Command(s.binPath,
		"--exe", binaryPath,
		"--functions=linkage",
		"--inlines",
		"--output-style=GNU",
		fmt.Sprintf("0x%x", ip),
	)
	out, err := cmd.Output()
	if err != nil {
		return Symbol{}, fmt.Errorf("llvm-symbolizer: %w", err)
	}

	// Output format (GNU style):
	//   functionName
	//   /path/to/file.go:lineNo
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return Symbol{Binary: binaryPath}, nil
	}

	name := strings.TrimSpace(lines[0])
	fileLine := strings.TrimSpace(lines[1])
	file, line := parseFileLine(fileLine)

	return Symbol{Name: name, File: file, Line: line, Binary: binaryPath}, nil
}

func (s *Symbolizer) resolveAddr2line(binaryPath string, ip uint64) (Symbol, error) {
	cmd := exec.Command(s.binPath,
		"-e", binaryPath,
		"-f",          // print function name
		"-C",          // demangle
		fmt.Sprintf("0x%x", ip),
	)
	out, err := cmd.Output()
	if err != nil {
		return Symbol{}, fmt.Errorf("addr2line: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return Symbol{Binary: binaryPath}, nil
	}

	name := strings.TrimSpace(lines[0])
	file, line := parseFileLine(strings.TrimSpace(lines[1]))
	return Symbol{Name: name, File: file, Line: line, Binary: binaryPath}, nil
}

func parseFileLine(s string) (string, int) {
	// Format: /absolute/path/file.go:42 or /path:0 (if unknown)
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, 0
	}
	line, err := strconv.Atoi(s[idx+1:])
	if err != nil {
		return s, 0
	}
	return s[:idx], line
}

// ─── PID → binary resolver ────────────────────────────────────────────────────

// BinaryForPID returns the main executable path for a given PID via /proc.
func BinaryForPID(pid uint32) (string, error) {
	link := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", link, err)
	}
	return target, nil
}

// ServiceNameForPID attempts to derive a logical service name for a PID.
// Strategy: read /proc/<pid>/cgroup and extract the Kubernetes pod name,
// then look up the pod's app label via the Downward API env var LSIG_SERVICE_LABEL.
// Falls back to the process comm name.
func ServiceNameForPID(pid uint32) string {
	// Try cgroup v2 path: /proc/<pid>/cgroup → last path component contains pod name
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(cgroupFile)
	if err != nil {
		return commForPID(pid)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 unified hierarchy: "0::/kubepods/burstable/pod<uid>/<container-id>"
		if strings.Contains(line, "kubepods") {
			parts := strings.Split(line, "/")
			for i, p := range parts {
				if strings.HasPrefix(p, "pod") && i+1 < len(parts) {
					// container ID segment
					containerID := parts[i+1]
					if label := serviceFromContainerID(containerID); label != "" {
						return label
					}
				}
			}
		}
	}
	return commForPID(pid)
}

func commForPID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// serviceFromContainerID looks up a container's app label via the kubelet
// read-only API or falls back to the LSIG_SERVICE_MAP env var.
// In practice this is injected at DaemonSet startup via a ConfigMap.
func serviceFromContainerID(containerID string) string {
	// Check environment-injected map: "containerID1=svcA,containerID2=svcB"
	mapping := os.Getenv("LSIG_SERVICE_MAP")
	if mapping == "" {
		return ""
	}
	for _, pair := range strings.Split(mapping, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 && strings.HasPrefix(containerID, kv[0]) {
			return kv[1]
		}
	}
	return ""
}

// ─── Repo-relative path stripping ────────────────────────────────────────────

// StripRepoRoot converts an absolute source path to a repo-relative path
// by stripping the known source root prefix.
func StripRepoRoot(absPath, repoRoot string) string {
	if repoRoot == "" {
		return absPath
	}
	rel, err := filepath.Rel(repoRoot, absPath)
	if err != nil {
		return absPath
	}
	return rel
}
