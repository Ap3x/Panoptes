package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Ap3x/Panoptes/detector/src/engine"
)

// Same layout and zone (UTC) as the Time field the service writes to pano.log
const logTimeLayout = "2006/01/02 15:04:05"

// defaultDetectionLog is %ProgramData%\Panoptes\Logs\detection.log, next to pano.log.
func defaultDetectionLog() string {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}
	return filepath.Join(root, "Panoptes", "Logs", "detection.log")
}

// detectionLog appends one JSON object per line (NDJSON) for each detection, like pano.log.
type detectionLog struct {
	mu sync.Mutex
	f  *os.File
}

func openDetectionLog(path string) (*detectionLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// Go opens files with FILE_SHARE_READ|FILE_SHARE_WRITE, so the log can be tailed while open
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	return &detectionLog{f: f}, nil
}

// Write appends the detection. reported says whether the service accepted it; replay mode,
// which has no service, passes nil and the field is left out.
func (l *detectionLog) Write(m engine.Match, now time.Time, reported *bool) error {
	rec := summary(m)
	rec["Time"] = now.UTC().Format(logTimeLayout)
	if reported != nil {
		rec["Reported"] = *reported
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", m.Rule.Name, err)
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(line) // one write per line, so a reader never sees half a record
	return err
}

func (l *detectionLog) Close() error {
	if l == nil {
		return nil
	}
	return l.f.Close()
}
