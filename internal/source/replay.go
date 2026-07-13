package source

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type Replay struct {
	path  string
	speed float64
	file  *os.File
}

func NewReplay(path string, speed float64) (*Replay, error) {
	if speed < 0 {
		return nil, fmt.Errorf("replay speed cannot be negative")
	}
	return &Replay{path: path, speed: speed}, nil
}

func (replay *Replay) Run(ctx context.Context, output chan<- model.Event) error {
	reader, err := replay.open()
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	var previous time.Time
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var event model.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("decode replay line %d: %w", line, err)
		}
		if event.Timestamp.IsZero() {
			return fmt.Errorf("replay line %d has no timestamp", line)
		}
		if !previous.IsZero() && event.Timestamp.Before(previous) {
			return fmt.Errorf("replay line %d is not time ordered", line)
		}
		if replay.speed > 0 && !previous.IsZero() {
			delay := time.Duration(float64(event.Timestamp.Sub(previous)) / replay.speed)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		previous = event.Timestamp
		event.EnsureDefaults(time.Now())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case output <- event:
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read replay: %w", err)
	}
	return nil
}

func (replay *Replay) open() (io.Reader, error) {
	if replay.path == "-" {
		return os.Stdin, nil
	}
	file, err := os.Open(replay.path)
	if err != nil {
		return nil, fmt.Errorf("open replay %s: %w", replay.path, err)
	}
	replay.file = file
	return file, nil
}

func (replay *Replay) Close() error {
	if replay.file != nil {
		return replay.file.Close()
	}
	return nil
}
