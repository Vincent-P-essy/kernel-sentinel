package enrich

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

var containerIDPattern = regexp.MustCompile(`(?:^|[-/:])([a-f0-9]{64})(?:\.scope)?(?:$|[\n/])`)

type ProcEnricher struct {
	root string
	host string
}

func NewProcEnricher(root string) *ProcEnricher {
	if root == "" {
		root = "/proc"
	}
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return &ProcEnricher{root: root, host: host}
}

func (enricher *ProcEnricher) Enrich(event *model.Event) {
	if event.Host == "" {
		event.Host = enricher.host
	}
	pidRoot := filepath.Join(enricher.root, strconv.FormatUint(uint64(event.Process.PID), 10))
	if executable, err := os.Readlink(filepath.Join(pidRoot, "exe")); err == nil {
		if event.Kind != model.EventExec || event.Process.Executable == "" {
			event.Process.Executable = strings.TrimSuffix(executable, " (deleted)")
		}
	}
	if event.Kind == model.EventExec {
		name := filepath.Base(event.Process.Executable)
		if name != "." && name != string(filepath.Separator) {
			event.Process.Name = name
		}
	}
	if comm, err := os.ReadFile(filepath.Join(pidRoot, "comm")); err == nil {
		if name := strings.TrimSpace(string(comm)); name != "" {
			event.Process.Name = name
		}
	}
	if commandLine, err := os.ReadFile(filepath.Join(pidRoot, "cmdline")); err == nil {
		parts := splitNull(commandLine)
		if len(parts) > 0 {
			event.Process.Arguments = parts
			event.Process.CommandLine = strings.Join(parts, " ")
		}
	}
	if ppid := readPPID(filepath.Join(pidRoot, "status")); ppid > 0 {
		event.Process.PPID = ppid
		parentComm, _ := os.ReadFile(filepath.Join(enricher.root, strconv.FormatUint(uint64(ppid), 10), "comm"))
		event.Process.ParentName = strings.TrimSpace(string(parentComm))
	}
	if cgroup, err := os.ReadFile(filepath.Join(pidRoot, "cgroup")); err == nil {
		event.Container.ID, event.Container.Runtime = parseContainer(string(cgroup))
	}
}

func splitNull(value []byte) []string {
	raw := strings.Split(strings.TrimRight(string(value), "\x00"), "\x00")
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func readPPID(path string) uint32 {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var ppid uint64
		if _, err := fmt.Sscanf(scanner.Text(), "PPid:\t%d", &ppid); err == nil {
			return uint32(ppid)
		}
	}
	return 0
}

func parseContainer(cgroup string) (string, string) {
	match := containerIDPattern.FindStringSubmatch(cgroup)
	if len(match) != 2 {
		return "", ""
	}
	runtime := "cgroup"
	lower := strings.ToLower(cgroup)
	switch {
	case strings.Contains(lower, "containerd") || strings.Contains(lower, "cri-containerd"):
		runtime = "containerd"
	case strings.Contains(lower, "docker"):
		runtime = "docker"
	case strings.Contains(lower, "crio") || strings.Contains(lower, "cri-o"):
		runtime = "cri-o"
	}
	return match[1], runtime
}
