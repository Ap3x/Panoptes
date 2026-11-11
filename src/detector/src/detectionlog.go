package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// Size at which the log continues in the next file, the same as pano.log's MAX_FILE_SIZE
const maxDetectionLogSize = 5 * 1024 * 1024

// detectionLog appends one JSON object per line (NDJSON) for each detection, like pano.log.
// Like pano.log it continues in detection1.log, detection2.log, ... once a file reaches
// maxSize, and on opening continues in the newest file already on disk.
type detectionLog struct {
	mu        sync.Mutex
	f         *os.File
	dir       string // folder of the files
	base, ext string // "detection", ".log"
	number    int    // current file: base.ext for 0, else base<number>.ext
	size      int64  // size of the current file
	maxSize   int64
}

func openDetectionLog(path string) (*detectionLog, error) {
	return openRotatingLog(path, maxDetectionLogSize)
}

func openRotatingLog(path string, maxSize int64) (*detectionLog, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	ext := filepath.Ext(path)
	l := &detectionLog{dir: dir, ext: ext, maxSize: maxSize,
		base: strings.TrimSuffix(filepath.Base(path), ext)}
	l.number = newestLogNumber(dir, l.base, ext)
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

// newestLogNumber is the highest N among base.ext (0) and baseN.ext in dir; 0 when there are none.
func newestLogNumber(dir, base, ext string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	newest := 0
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		lb, le := strings.ToLower(base), strings.ToLower(ext)
		if e.IsDir() || !strings.HasPrefix(name, lb) || !strings.HasSuffix(name, le) ||
			len(name) <= len(lb)+len(le) {
			continue
		}
		digits := name[len(lb) : len(name)-len(le)]
		if len(digits) > 9 || strings.Trim(digits, "0123456789") != "" {
			continue
		}
		if n, err := strconv.Atoi(digits); err == nil && n > newest {
			newest = n
		}
	}
	return newest
}

func (l *detectionLog) path() string {
	name := l.base
	if l.number > 0 {
		name += strconv.Itoa(l.number)
	}
	return filepath.Join(l.dir, name+l.ext)
}

// open opens the current file, moving on to the next number while it is already full.
func (l *detectionLog) open() error {
	for {
		// Go opens files with FILE_SHARE_READ|FILE_SHARE_WRITE, so the log can be tailed while open
		f, err := os.OpenFile(l.path(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if st.Size() < l.maxSize {
			l.f, l.size = f, st.Size()
			return nil
		}
		f.Close()
		l.number++
	}
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
	if l.f == nil || l.size >= l.maxSize {
		// Full (or a previous open failed): continue in the next file
		if l.f != nil {
			l.f.Close()
			l.f = nil
			l.number++
		}
		if err := l.open(); err != nil {
			return err
		}
	}
	n, err := l.f.Write(line) // one write per line, so a reader never sees half a record
	l.size += int64(n)
	return err
}

func (l *detectionLog) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}
