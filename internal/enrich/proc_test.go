package enrich

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

func TestProcEnricherReadsProcessAndContainerContext(t *testing.T) {
	root := t.TempDir()
	pidRoot := filepath.Join(root, "42")
	parentRoot := filepath.Join(root, "7")
	if err := os.MkdirAll(pidRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(parentRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("a", 64)
	files := map[string]string{
		filepath.Join(pidRoot, "cmdline"): "bash\x00-c\x00id\x00",
		filepath.Join(pidRoot, "comm"):    "bash\n",
		filepath.Join(pidRoot, "status"):  "Name:\tbash\nPPid:\t7\n",
		filepath.Join(pidRoot, "cgroup"):  "0::/system.slice/docker-" + containerID + ".scope\n",
		filepath.Join(parentRoot, "comm"): "systemd\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/usr/bin/bash", filepath.Join(pidRoot, "exe")); err != nil {
		t.Fatal(err)
	}
	event := model.Event{Process: model.Process{PID: 42}}
	NewProcEnricher(root).Enrich(&event)

	if event.Process.Executable != "/usr/bin/bash" || event.Process.Name != "bash" || event.Process.CommandLine != "bash -c id" {
		t.Fatalf("process not enriched: %#v", event.Process)
	}
	if event.Process.PPID != 7 || event.Process.ParentName != "systemd" {
		t.Fatalf("parent not enriched: %#v", event.Process)
	}
	if event.Container.ID != containerID || event.Container.Runtime != "docker" {
		t.Fatalf("container not enriched: %#v", event.Container)
	}
}

func TestProcEnricherPreservesExecPathAndRefreshesName(t *testing.T) {
	root := t.TempDir()
	pidRoot := filepath.Join(root, "42")
	if err := os.MkdirAll(pidRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", filepath.Join(pidRoot, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidRoot, "comm"), []byte("payload-worker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	event := model.Event{
		Kind:    model.EventExec,
		Process: model.Process{PID: 42, Name: "old-shell", Executable: "/tmp/payload"},
	}
	NewProcEnricher(root).Enrich(&event)
	if event.Process.Executable != "/tmp/payload" || event.Process.Name != "payload-worker" {
		t.Fatalf("exec identity not preserved: %#v", event.Process)
	}

	fallback := model.Event{
		Kind:    model.EventExec,
		Process: model.Process{PID: 404, Name: "old-shell", Executable: "/dev/shm/update-check"},
	}
	NewProcEnricher(root).Enrich(&fallback)
	if fallback.Process.Name != "update-check" || fallback.Process.Executable != "/dev/shm/update-check" {
		t.Fatalf("exec fallback not applied: %#v", fallback.Process)
	}
}

func TestSplitNullAndUnknownContainer(t *testing.T) {
	if values := splitNull([]byte("one\x00\x00two\x00")); len(values) != 2 {
		t.Fatalf("unexpected values: %#v", values)
	}
	if id, runtime := parseContainer("0::/user.slice"); id != "" || runtime != "" {
		t.Fatalf("unexpected container: %s %s", id, runtime)
	}
}
