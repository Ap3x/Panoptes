// Package engine runs compiled rules over a stream of events.
//
// For each rule it keeps partial matches keyed by the join value (e.g. the target PID). When an
// event matches step i of a rule, the partials for that key waiting at step i advance; reaching
// the last step produces a Match. Partials older than the rule's maxspan are dropped. This is
// the `sequence by ... with maxspan=...` / `until` subset of EQL.
//
// Steps may arrive up to Tolerance out of order. Driver and hook events are timestamped by
// different clocks (system time in the driver, ETW's QPC-based time for hooks) that drift apart,
// so a hook event can carry a time just before the ProcessCreated that it follows. Sorting by
// time then puts it first, where no partial is waiting for it yet. An event that matches a later
// step with nothing waiting for it is kept for Tolerance; when a partial reaches that step, the
// kept event can complete it. This only applies across pipelines (a hook event and a driver
// event): events from one pipeline share a clock, so their order stands.
//
// Engine is not safe for concurrent use: feed it from one goroutine.
package engine

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Ap3x/Panoptes/detector/src/rules"
)

// Most partials kept per (rule, key). A process that matches step 1 over and over (e.g. many
// RWX allocations) otherwise grows the state without bound; the oldest are dropped first.
const maxPartialsPerKey = 8

type Event struct {
	Seq    uint64 // the event's Seq in pano.log (DetectorEvent.sequence); the line number when replaying a log without Seq
	Time   time.Time
	Fields map[string]any // the decoded JSON log object
}

type Match struct {
	Rule   *rules.Rule
	Key    string
	Events []Event
}

// TargetPID is the process the rule's action applies to: Rule.Target read from the last event.
func (m Match) TargetPID() (uint32, bool) {
	v, ok := m.Events[len(m.Events)-1].Fields[m.Rule.Target].(float64)
	return uint32(v), ok
}

// TargetImage is TargetPID's image as the matched events give it: the Image of an event that
// process logged (for ProcessCreated, the new process), or the TargetImage of a hook event
// acting on it. The newest event that names it wins. "" when no event does.
func (m Match) TargetImage() string {
	pid, ok := m.TargetPID()
	if !ok {
		return ""
	}
	for i := len(m.Events) - 1; i >= 0; i-- {
		f := m.Events[i].Fields
		if p, ok := f["PID"].(float64); ok && uint32(p) == pid {
			if s, _ := f["Image"].(string); s != "" {
				return s
			}
		}
		if p, ok := f["TargetProcessId"].(float64); ok && uint32(p) == pid {
			if s, _ := f["TargetImage"].(string); s != "" {
				return s
			}
		}
	}
	return ""
}

// Sequences are the Seq of each matched event, in match order: the events' Seq field in
// pano.log, which names their lines there.
func (m Match) Sequences() []uint64 {
	out := make([]uint64, len(m.Events))
	for i, ev := range m.Events {
		out[i] = ev.Seq
	}
	return out
}

type partial struct {
	next   int // index of the step this partial waits for
	start  time.Time
	events []Event
}

// early is an event that matched step `step` of a rule before any partial was waiting there
type early struct {
	step int
	ev   Event
}

type Engine struct {
	// How far before the previous step's event a step's event may be and still match. 0 means
	// steps must arrive in order
	Tolerance time.Duration

	rules []*rules.Rule
	state map[*rules.Rule]map[string][]*partial
	early map[*rules.Rule]map[string][]early
}

func New(rs []*rules.Rule) *Engine {
	e := &Engine{
		rules: rs,
		state: make(map[*rules.Rule]map[string][]*partial),
		early: make(map[*rules.Rule]map[string][]early),
	}
	for _, r := range rs {
		e.state[r] = make(map[string][]*partial)
		e.early[r] = make(map[string][]early)
	}
	return e
}

// Process feeds one event to every rule and returns the rules it completed.
func (e *Engine) Process(ev Event) []Match {
	var out []Match
	for _, r := range e.rules {
		out = append(out, e.processRule(r, ev)...)
	}
	return out
}

func (e *Engine) processRule(r *rules.Rule, ev Event) []Match {
	byKey := e.state[r]

	if r.Until != nil {
		if key := keyOf(ev.Fields, r.Until.By); key != "" && r.Until.Match(ev.Fields) {
			e.reset(r, key)
		}
	}

	// Later steps first, so one event cannot advance the same partial twice
	for i := len(r.Steps) - 1; i >= 1; i-- {
		step := r.Steps[i]
		key := keyOf(ev.Fields, step.By)
		if key == "" || !step.Match(ev.Fields) {
			continue
		}
		advanced := false
		for _, p := range byKey[key] {
			if p.next != i || expired(r, p, ev.Time) {
				continue
			}
			advanced = true
			p.next++
			p.events = append(p.events, ev)
			if m, ok := e.complete(r, key, p); ok {
				return []Match{m}
			}
		}
		if !advanced {
			e.keepEarly(r, key, i, ev)
		}
	}

	first := r.Steps[0]
	if !first.Match(ev.Fields) {
		return nil
	}
	if len(r.Steps) == 1 {
		return []Match{{Rule: r, Key: keyOf(ev.Fields, first.By), Events: []Event{ev}}}
	}
	key := keyOf(ev.Fields, first.By)
	if key == "" {
		return nil
	}
	p := &partial{next: 1, start: ev.Time, events: []Event{ev}}
	list := append(byKey[key], p)
	if len(list) > maxPartialsPerKey {
		list = list[len(list)-maxPartialsPerKey:]
	}
	byKey[key] = list
	if m, ok := e.complete(r, key, p); ok {
		return []Match{m}
	}
	return nil
}

// complete advances p through any of its next steps that already arrived early, then reports
// it if it reached the last step. A match resets the key, so a burst of matching events gives
// one alert.
func (e *Engine) complete(r *rules.Rule, key string, p *partial) (Match, bool) {
	for p.next < len(r.Steps) {
		ev, ok := e.takeEarly(r, key, p)
		if !ok {
			return Match{}, false
		}
		p.next++
		p.events = append(p.events, ev)
	}
	e.reset(r, key)
	return Match{Rule: r, Key: key, Events: p.events}, true
}

// takeEarly removes and returns the first kept event for p's next step that is within
// Tolerance before p's latest event, and that p does not already hold (an event can match
// more than one step). Only an event from the other pipeline qualifies: events from the same
// one share a clock, so their order is real.
func (e *Engine) takeEarly(r *rules.Rule, key string, p *partial) (Event, bool) {
	list := e.early[r][key]
	prev := p.events[len(p.events)-1]
	from := prev.Time.Add(-e.Tolerance)
	for i, k := range list {
		if k.step != p.next || k.ev.Time.Before(from) || expired(r, p, k.ev.Time) ||
			source(k.ev) == source(prev) || holds(p, k.ev) {
			continue
		}
		e.early[r][key] = append(list[:i:i], list[i+1:]...)
		return k.ev, true
	}
	return Event{}, false
}

// source is the pipeline that timestamped ev: "Hook" for hook events, "" for the driver's and
// the service's own
func source(ev Event) string {
	s, _ := ev.Fields["Source"].(string)
	return s
}

func holds(p *partial, ev Event) bool {
	for _, held := range p.events {
		if held.Seq == ev.Seq {
			return true
		}
	}
	return false
}

// keepEarly keeps ev, which matched step `step` with no partial waiting for it, for Tolerance
func (e *Engine) keepEarly(r *rules.Rule, key string, step int, ev Event) {
	if e.Tolerance <= 0 {
		return
	}
	list := pruneEarly(e.early[r][key], ev.Time.Add(-e.Tolerance))
	list = append(list, early{step: step, ev: ev})
	if len(list) > maxPartialsPerKey {
		list = list[len(list)-maxPartialsPerKey:]
	}
	e.early[r][key] = list
}

// pruneEarly drops kept events from before `from`, in place
func pruneEarly(list []early, from time.Time) []early {
	kept := list[:0]
	for _, k := range list {
		if !k.ev.Time.Before(from) {
			kept = append(kept, k)
		}
	}
	return kept
}

// reset forgets everything about key for r: its partials and the events kept for them
func (e *Engine) reset(r *rules.Rule, key string) {
	delete(e.state[r], key)
	delete(e.early[r], key)
}

// Sweep drops partials whose maxspan has passed and early events older than Tolerance. Call it
// periodically; Process only skips expired partials, it does not free them.
func (e *Engine) Sweep(now time.Time) {
	for _, byKey := range e.early {
		for key, list := range byKey {
			if list = pruneEarly(list, now.Add(-e.Tolerance)); len(list) == 0 {
				delete(byKey, key)
			} else {
				byKey[key] = list
			}
		}
	}
	for r, byKey := range e.state {
		for key, list := range byKey {
			kept := list[:0]
			for _, p := range list {
				if !expired(r, p, now) {
					kept = append(kept, p)
				}
			}
			if len(kept) == 0 {
				delete(byKey, key)
			} else {
				byKey[key] = kept
			}
		}
	}
}

func expired(r *rules.Rule, p *partial, now time.Time) bool {
	return r.MaxSpan > 0 && now.Sub(p.start) > r.MaxSpan
}

// keyOf renders a join field as a map key. JSON numbers decode as float64, which fmt would
// print in exponent form for large values, so they are formatted explicitly. 0 means unknown
// (the hook logs TargetProcessId 0 when the handle cannot be queried), so it never joins: two
// unrelated unknown targets must not complete each other's sequences.
func keyOf(fields map[string]any, field string) string {
	if field == "" {
		return ""
	}
	switch v := fields[field].(type) {
	case nil:
		return ""
	case float64:
		if v == 0 {
			return ""
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}
