package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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
