package model

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type EventKind string

const (
	EventExec     EventKind = "process.exec"
	EventFork     EventKind = "process.fork"
	EventFileOpen EventKind = "file.open"
	EventConnect  EventKind = "network.connect"
	EventSetUID   EventKind = "privilege.setuid"
)

type Process struct {
	PID         uint32   `json:"pid"`
	TID         uint32   `json:"tid"`
	PPID        uint32   `json:"ppid,omitempty"`
	UID         uint32   `json:"uid"`
	GID         uint32   `json:"gid"`
	Name        string   `json:"name"`
	Executable  string   `json:"executable,omitempty"`
	Arguments   []string `json:"arguments,omitempty"`
	CommandLine string   `json:"command_line,omitempty"`
	ParentName  string   `json:"parent_name,omitempty"`
}

type File struct {
	Path  string `json:"path"`
	Flags uint32 `json:"flags"`
}

type Network struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	FD      int32  `json:"fd"`
}

type Privilege struct {
	TargetUID uint32 `json:"target_uid"`
}

type Container struct {
	ID      string `json:"id,omitempty"`
	Runtime string `json:"runtime,omitempty"`
	Pod     string `json:"pod,omitempty"`
	Image   string `json:"image,omitempty"`
}

type Outcome struct {
	Success    bool  `json:"success"`
	ReturnCode int64 `json:"return_code"`
}

type Event struct {
	SchemaVersion string      `json:"schema_version"`
	ID            string      `json:"id"`
	Timestamp     time.Time   `json:"timestamp"`
	ObservedAt    time.Time   `json:"observed_at"`
	Kind          EventKind   `json:"kind"`
	Host          string      `json:"host"`
	Process       Process     `json:"process"`
	File          *File       `json:"file,omitempty"`
	Network       *Network    `json:"network,omitempty"`
	Privilege     *Privilege  `json:"privilege,omitempty"`
	Container     Container   `json:"container"`
	Outcome       Outcome     `json:"outcome"`
	ScenarioID    string      `json:"scenario_id,omitempty"`
	Labels        []string    `json:"labels,omitempty"`
	Raw           interface{} `json:"raw,omitempty"`
}

func (event *Event) EnsureDefaults(now time.Time) {
	if event.SchemaVersion == "" {
		event.SchemaVersion = "1.0"
	}
	if event.ObservedAt.IsZero() {
		event.ObservedAt = now
	}
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d-%d-%s", event.Timestamp.UnixNano(), event.Process.TID, event.Kind)
	}
}

func (event Event) Field(name string) (interface{}, bool) {
	switch name {
	case "id":
		return event.ID, true
	case "kind":
		return string(event.Kind), true
	case "host":
		return event.Host, true
	case "scenario_id":
		return event.ScenarioID, event.ScenarioID != ""
	case "process.pid":
		return int64(event.Process.PID), true
	case "process.tid":
		return int64(event.Process.TID), true
	case "process.ppid":
		return int64(event.Process.PPID), event.Process.PPID != 0
	case "process.uid":
		return int64(event.Process.UID), true
	case "process.gid":
		return int64(event.Process.GID), true
	case "process.name":
		return event.Process.Name, event.Process.Name != ""
	case "process.executable":
		return event.Process.Executable, event.Process.Executable != ""
	case "process.command_line":
		return event.Process.CommandLine, event.Process.CommandLine != ""
	case "process.arguments":
		return strings.Join(event.Process.Arguments, " "), len(event.Process.Arguments) > 0
	case "process.parent.name":
		return event.Process.ParentName, event.Process.ParentName != ""
	case "file.path":
		if event.File != nil {
			return event.File.Path, true
		}
	case "file.flags":
		if event.File != nil {
			return int64(event.File.Flags), true
		}
	case "file.write":
		if event.File != nil {
			return event.File.Flags&3 != 0, true
		}
	case "file.create":
		if event.File != nil {
			return event.File.Flags&64 != 0, true
		}
	case "file.truncate":
		if event.File != nil {
			return event.File.Flags&512 != 0, true
		}
	case "network.family":
		if event.Network != nil {
			return event.Network.Family, true
		}
	case "network.address":
		if event.Network != nil {
			return event.Network.Address, true
		}
	case "network.port":
		if event.Network != nil {
			return int64(event.Network.Port), true
		}
	case "network.external":
		if event.Network != nil {
			ip := net.ParseIP(event.Network.Address)
			return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified(), true
		}
	case "container.id":
		return event.Container.ID, event.Container.ID != ""
	case "container.runtime":
		return event.Container.Runtime, event.Container.Runtime != ""
	case "container.image":
		return event.Container.Image, event.Container.Image != ""
	case "outcome.success":
		return event.Outcome.Success, true
	case "outcome.return_code":
		return event.Outcome.ReturnCode, true
	case "privilege.target_uid":
		if event.Privilege != nil {
			return int64(event.Privilege.TargetUID), true
		}
	}
	return nil, false
}

func FieldString(event Event, name string) string {
	value, ok := event.Field(name)
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case int64:
		return strconv.FormatInt(typed, 10)
	case bool:
		return strconv.FormatBool(typed)
	default:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	}
}
