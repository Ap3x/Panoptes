package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ap3x/Panoptes/detector/src/engine"
	"github.com/Ap3x/Panoptes/detector/src/rules"
)

func TestDetectionLogAppendsJSONLines(t *testing.T) {
	r, err := rules.Compile(rules.File{
		Name: "remote_rwx_allocation", Description: "RWX memory allocated in another process",
		Severity: "medium", Sequence: []rules.StepFile{{Where: `Event == "ExecutableAllocated"`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := engine.Match{Rule: r, Events: []engine.Event{{Seq: 7, Fields: map[string]any{
		"Event": "ExecutableAllocated", "PID": 14388.0, "TargetProcessId": 13928.0,
		"Image": `C:\a "quoted"\path.exe`, // must stay one valid line once escaped
	}}}}

	path := filepath.Join(t.TempDir(), "Logs", "detection.log") // the folder does not exist yet
	now := time.Date(2026, 11, 10, 21, 5, 26, 0, time.UTC)
	reported := true
	for i := 0; i < 2; i++ {
		l, err := openDetectionLog(path) // reopening appends instead of truncating
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Write(m, now, map[bool]*bool{true: &reported, false: nil}[i == 0]); err != nil {
			t.Fatal(err)
		}
		l.Close()
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", len(recs)+1, err, sc.Text())
		}
		recs = append(recs, rec)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 lines, got %d", len(recs))
	}
	first := recs[0]
	if first["Rule"] != "remote_rwx_allocation" || first["Time"] != "2026/11/10 21:05:26" ||
		first["TargetPID"] != 14388.0 || first["Reported"] != true || first["Severity"] != "medium" {
		t.Fatalf("unexpected record: %v", first)
	}
	if _, ok := recs[1]["Reported"]; ok {
		t.Fatalf("replay record should not carry Reported: %v", recs[1])
	}
	if ev := first["Events"].([]any)[0].(map[string]any); ev["Image"] != `C:\a "quoted"\path.exe` {
		t.Fatalf("event fields not preserved: %v", ev)
	}
}

func TestDetectionLogRotates(t *testing.T) {
	r, err := rules.Compile(rules.File{
		Name: "r", Description: "d", Severity: "low",
		Sequence: []rules.StepFile{{Where: `Event == "X"`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := engine.Match{Rule: r, Events: []engine.Event{{Fields: map[string]any{"Event": "X"}}}}
	dir := t.TempDir()
	path := filepath.Join(dir, "detection.log")
	lines := func(name string) int {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return -1
		}
		return strings.Count(string(b), "\n")
	}

	// Each record is ~150 bytes, so a 400-byte limit fits three before moving on
	l, err := openRotatingLog(path, 400)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := l.Write(m, time.Now(), nil); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	if got := []int{lines("detection.log"), lines("detection1.log"), lines("detection2.log")}; got[0] != 3 || got[1] != 3 || got[2] != 1 {
		t.Fatalf("lines per file = %v, want [3 3 1]", got)
	}

	// Reopening continues in the newest file (detection2.log), not detection.log
	l, err = openRotatingLog(path, 400)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(m, time.Now(), nil)
	l.Close()
	if lines("detection.log") != 3 || lines("detection2.log") != 2 {
		t.Fatalf("reopen wrote to the wrong file: %d, %d", lines("detection.log"), lines("detection2.log"))
	}

	// A newest file that is already full starts the next one; other names are ignored
	os.WriteFile(filepath.Join(dir, "detection9.log"), make([]byte, 500), 0o644)
	os.WriteFile(filepath.Join(dir, "detection99.log.bak"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "detectionX50.log"), nil, 0o644)
	l, err = openRotatingLog(path, 400)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(m, time.Now(), nil)
	l.Close()
	if lines("detection10.log") != 1 {
		t.Fatalf("want the record in detection10.log, got %d lines", lines("detection10.log"))
	}
}
