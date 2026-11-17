package engine

import (
	"testing"
	"time"

	"github.com/Ap3x/Panoptes/detector/src/rules"
)

var t0 = time.Date(2026, 11, 10, 6, 41, 24, 0, time.UTC)

func ev(seq uint64, offset time.Duration, fields map[string]any) Event {
	return Event{Seq: seq, Time: t0.Add(offset), Fields: fields}
}

func compile(t *testing.T, f rules.File) *rules.Rule {
	t.Helper()
	r, err := rules.Compile(f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The process_hollowing rule from rules/injection.yaml: steps join on different fields
func hollowing(t *testing.T) *rules.Rule {
	return compile(t, rules.File{
		Name: "process_hollowing", MaxSpan: 5 * time.Second,
		Sequence: []rules.StepFile{
			{Where: `Event == "ProcessCreated"`, By: "PID"},
			{Where: `Event == "PEWritten" && Remote == true`, By: "TargetProcessId"},
		},
	})
}

func TestSequenceAcrossJoinFields(t *testing.T) {
	e := New([]*rules.Rule{hollowing(t)})
	if m := e.Process(ev(1, 0, map[string]any{"Event": "ProcessCreated", "PID": 14000.0})); len(m) != 0 {
		t.Fatalf("matched on first step: %v", m)
	}
	// A write into a different process does not complete it
	if m := e.Process(ev(2, time.Second, map[string]any{"Event": "PEWritten", "Remote": true, "PID": 10776.0, "TargetProcessId": 999.0})); len(m) != 0 {
		t.Fatalf("matched the wrong key: %v", m)
	}
	m := e.Process(ev(3, time.Second, map[string]any{"Event": "PEWritten", "Remote": true, "PID": 10776.0, "TargetProcessId": 14000.0}))
	if len(m) != 1 || m[0].Key != "14000" {
		t.Fatalf("want one match on 14000, got %v", m)
	}
	if pid, _ := m[0].TargetPID(); pid != 10776 {
		t.Fatalf("target PID %d, want the injector 10776", pid)
	}
}

func TestTargetImageAndSequences(t *testing.T) {
	created := ev(10, 0, map[string]any{"Event": "ProcessCreated", "PID": 14000.0, "Image": `C:\victim.exe`})
	written := ev(11, time.Second, map[string]any{"Event": "PEWritten", "Remote": true, "PID": 10776.0,
		"Image": `C:\injector.exe`, "TargetProcessId": 14000.0, "TargetImage": `C:\victim.exe`})

	// target: PID of the last event, the injector: its own Image
	m := New([]*rules.Rule{hollowing(t)})
	m.Process(created)
	got := m.Process(written)
	if len(got) != 1 || got[0].TargetImage() != `C:\injector.exe` {
		t.Fatalf("want the injector's image, got %v", got)
	}
	if seqs := got[0].Sequences(); len(seqs) != 2 || seqs[0] != 10 || seqs[1] != 11 {
		t.Fatalf("sequences = %v, want [10 11]", seqs)
	}

	// target: TargetProcessId, the victim: the hook event's TargetImage, not its Image
	victim := hollowing(t)
	victim.Target = "TargetProcessId"
	m = New([]*rules.Rule{victim})
	m.Process(created)
	if got := m.Process(written); len(got) != 1 || got[0].TargetImage() != `C:\victim.exe` {
		t.Fatalf("want the victim's image, got %v", got)
	}
}

func TestMaxSpan(t *testing.T) {
	e := New([]*rules.Rule{hollowing(t)})
	e.Process(ev(1, 0, map[string]any{"Event": "ProcessCreated", "PID": 14000.0}))
	if m := e.Process(ev(2, 6*time.Second, map[string]any{"Event": "PEWritten", "Remote": true, "TargetProcessId": 14000.0})); len(m) != 0 {
		t.Fatalf("matched outside maxspan: %v", m)
	}
}

func TestUnknownTargetNeverJoins(t *testing.T) {
	r := compile(t, rules.File{
		Name: "apc", By: "TargetProcessId", MaxSpan: 10 * time.Second,
		Sequence: []rules.StepFile{
			{Where: `Event == "ExecutableAllocated" && Remote == true`},
			{Where: `Event == "ApcQueued" && Remote == true`},
		},
	})
	e := New([]*rules.Rule{r})
	e.Process(ev(1, 0, map[string]any{"Event": "ExecutableAllocated", "Remote": true, "TargetProcessId": 0.0}))
	if m := e.Process(ev(2, time.Second, map[string]any{"Event": "ApcQueued", "Remote": true, "TargetProcessId": 0.0})); len(m) != 0 {
		t.Fatalf("TargetProcessId 0 joined two unrelated events: %v", m)
	}
}

func TestUntil(t *testing.T) {
	r := compile(t, rules.File{
		Name: "inject", By: "TargetProcessId", MaxSpan: 10 * time.Second,
		Until: &rules.StepFile{Where: `Event == "ProcessTerminated"`, By: "PID"},
		Sequence: []rules.StepFile{
			{Where: `Event == "ExecutableAllocated"`},
			{Where: `Event == "RemoteThreadCreated"`},
		},
	})
	e := New([]*rules.Rule{r})
	e.Process(ev(1, 0, map[string]any{"Event": "ExecutableAllocated", "TargetProcessId": 50.0}))
	e.Process(ev(2, time.Second, map[string]any{"Event": "ProcessTerminated", "PID": 50.0}))
	if m := e.Process(ev(3, 2*time.Second, map[string]any{"Event": "RemoteThreadCreated", "TargetProcessId": 50.0})); len(m) != 0 {
		t.Fatalf("matched after the target exited: %v", m)
	}
}

// The order seen in pano.log: the driver's ProcessTerminated for the victim was logged before
// the hook events that happened earlier. With a ProcessTerminated `until`, processing in arrival
// order loses the detection; reordering by event time keeps it.
func TestReorderRestoresSequence(t *testing.T) {
	rule := func() *rules.Rule {
		return compile(t, rules.File{
			Name: "hollow", MaxSpan: 5 * time.Second,
			Until: &rules.StepFile{Where: `Event == "ProcessTerminated"`, By: "PID"},
			Sequence: []rules.StepFile{
				{Where: `Event == "ProcessCreated"`, By: "PID"},
				{Where: `Event == "PEWritten"`, By: "TargetProcessId"},
			},
		})
	}
	arrival := []Event{
		ev(1, 0, map[string]any{"Event": "ProcessCreated", "PID": 14000.0}),
		ev(2, 900*time.Millisecond, map[string]any{"Event": "ProcessTerminated", "PID": 14000.0}),
		ev(3, 300*time.Millisecond, map[string]any{"Event": "PEWritten", "TargetProcessId": 14000.0}), // hook: late
	}

	inOrder := New([]*rules.Rule{rule()})
	var unordered int
	for _, e := range arrival {
		unordered += len(inOrder.Process(e))
	}
	if unordered != 0 {
		t.Fatalf("expected the arrival order to miss the sequence (the test premise), got %d", unordered)
	}

	eng := New([]*rules.Rule{rule()})
	ro := NewReorderer(2 * time.Second)
	var matches int
	for _, e := range arrival {
		ro.Push(e)
		for _, r := range ro.Pop(ro.ReplayWatermark()) {
			matches += len(eng.Process(r))
		}
	}
	for _, r := range ro.Flush() {
		matches += len(eng.Process(r))
	}
	if matches != 1 {
		t.Fatalf("want 1 match after reordering, got %d", matches)
	}
	if ro.Late != 0 {
		t.Fatalf("late = %d, want 0", ro.Late)
	}
}

// The hook's clock runs slightly behind the driver's, so the write into the new process is
// stamped (and sorted) before its ProcessCreated
func TestToleranceMatchesHookEventStampedEarly(t *testing.T) {
	created := ev(2, 0, map[string]any{"Event": "ProcessCreated", "PID": 14000.0})
	written := ev(1, -800*time.Millisecond, map[string]any{"Event": "PEWritten", "Source": "Hook",
		"Remote": true, "PID": 10776.0, "TargetProcessId": 14000.0})

	strict := New([]*rules.Rule{hollowing(t)})
	strict.Process(written)
	if m := strict.Process(created); len(m) != 0 {
		t.Fatalf("matched out of order with no tolerance: %v", m)
	}

	e := New([]*rules.Rule{hollowing(t)})
	e.Tolerance = 2 * time.Second
	if m := e.Process(written); len(m) != 0 {
		t.Fatalf("matched before the first step: %v", m)
	}
	m := e.Process(created)
	if len(m) != 1 || m[0].Key != "14000" || len(m[0].Events) != 2 {
		t.Fatalf("want one two-event match on 14000, got %v", m)
	}
	if pid, _ := m[0].TargetPID(); pid != 10776 {
		t.Fatalf("target PID %d, want the injector 10776", pid)
	}
	// The kept event was used up, and the key reset
	if m := e.Process(ev(3, time.Second, created.Fields)); len(m) != 0 {
		t.Fatalf("kept event matched twice: %v", m)
	}
}

func TestToleranceLimits(t *testing.T) {
	created := map[string]any{"Event": "ProcessCreated", "PID": 14000.0}
	written := func(offset time.Duration) Event {
		return ev(1, offset, map[string]any{"Event": "PEWritten", "Source": "Hook", "Remote": true,
			"TargetProcessId": 14000.0})
	}

	t.Run("too early", func(t *testing.T) {
		e := New([]*rules.Rule{hollowing(t)})
		e.Tolerance = 2 * time.Second
		e.Process(written(-3 * time.Second))
		if m := e.Process(ev(2, 0, created)); len(m) != 0 {
			t.Fatalf("matched an event further back than the tolerance: %v", m)
		}
	})

	t.Run("swept", func(t *testing.T) {
		e := New([]*rules.Rule{hollowing(t)})
		e.Tolerance = 2 * time.Second
		e.Process(written(-time.Second))
		e.Sweep(t0.Add(2 * time.Second))
		if m := e.Process(ev(2, 0, created)); len(m) != 0 {
			t.Fatalf("matched an event Sweep should have dropped: %v", m)
		}
	})

	t.Run("same pipeline", func(t *testing.T) {
		// Two hook events share a clock: a thread created before the allocation is not a match
		r := compile(t, rules.File{
			Name: "inject", By: "TargetProcessId", MaxSpan: 10 * time.Second,
			Sequence: []rules.StepFile{
				{Where: `Event == "ExecutableAllocated"`},
				{Where: `Event == "RemoteThreadCreated"`},
			},
		})
		e := New([]*rules.Rule{r})
		e.Tolerance = 2 * time.Second
		e.Process(ev(1, 0, map[string]any{"Event": "RemoteThreadCreated", "Source": "Hook", "TargetProcessId": 50.0}))
		if m := e.Process(ev(2, time.Second, map[string]any{"Event": "ExecutableAllocated", "Source": "Hook", "TargetProcessId": 50.0})); len(m) != 0 {
			t.Fatalf("matched two hook events out of order: %v", m)
		}
	})

	t.Run("until", func(t *testing.T) {
		r := compile(t, rules.File{
			Name: "hollow", MaxSpan: 5 * time.Second,
			Until: &rules.StepFile{Where: `Event == "ProcessTerminated"`, By: "PID"},
			Sequence: []rules.StepFile{
				{Where: `Event == "ProcessCreated"`, By: "PID"},
				{Where: `Event == "PEWritten"`, By: "TargetProcessId"},
			},
		})
		e := New([]*rules.Rule{r})
		e.Tolerance = 2 * time.Second
		e.Process(written(-time.Second))
		e.Process(ev(2, -500*time.Millisecond, map[string]any{"Event": "ProcessTerminated", "PID": 14000.0}))
		if m := e.Process(ev(3, 0, created)); len(m) != 0 {
			t.Fatalf("matched an event from before the process with that PID exited: %v", m)
		}
	})
}

func TestReorderWatermarkAndLate(t *testing.T) {
	ro := NewReorderer(time.Second)
	ro.Push(ev(1, 2*time.Second, nil))
	ro.Push(ev(2, 0, nil))
	ro.Push(ev(3, 0, nil))
	got := ro.Pop(ro.ReplayWatermark()) // watermark t0+1s
	if len(got) != 2 || got[0].Seq != 2 || got[1].Seq != 3 {
		t.Fatalf("want seq 2,3 (ties keep arrival order), got %v", got)
	}
	ro.Push(ev(4, 500*time.Millisecond, nil)) // after the newest released event (t0): on time
	ro.Push(ev(5, -time.Second, nil))         // older than released t0: late
	if ro.Late != 1 {
		t.Fatalf("late = %d, want 1", ro.Late)
	}
	rest := ro.Flush()
	if len(rest) != 3 || rest[0].Seq != 5 || rest[2].Seq != 1 {
		t.Fatalf("flush order wrong: %v", rest)
	}
}
