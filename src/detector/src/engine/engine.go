// Package engine runs compiled rules over a stream of events.
//
// For each rule it keeps partial matches keyed by the join value (e.g. the target PID). When an
// event matches step i of a rule, the partials for that key waiting at step i advance; reaching
// the last step produces a Match. Partials older than the rule's maxspan are dropped. This is
// the `sequence by ... with maxspan=...` / `until` subset of EQL.
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
	Seq    uint64 // DetectorEvent.sequence, or the line number when replaying a log
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

type partial struct {
	next   int // index of the step this partial waits for
	start  time.Time
	events []Event
}

type Engine struct {
	rules []*rules.Rule
	state map[*rules.Rule]map[string][]*partial
}

func New(rs []*rules.Rule) *Engine {
	e := &Engine{rules: rs, state: make(map[*rules.Rule]map[string][]*partial)}
	for _, r := range rs {
		e.state[r] = make(map[string][]*partial)
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
			delete(byKey, key)
		}
	}

	// Later steps first, so one event cannot advance the same partial twice
	for i := len(r.Steps) - 1; i >= 1; i-- {
		step := r.Steps[i]
		key := keyOf(ev.Fields, step.By)
		if key == "" || len(byKey[key]) == 0 || !step.Match(ev.Fields) {
			continue
		}
		for _, p := range byKey[key] {
			if p.next != i || expired(r, p, ev.Time) {
				continue
			}
			p.next++
			p.events = append(p.events, ev)
			if p.next == len(r.Steps) {
				// Report once and reset this key, so a burst of matching events gives one alert
				delete(byKey, key)
				return []Match{{Rule: r, Key: key, Events: p.events}}
			}
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
	list := append(byKey[key], &partial{next: 1, start: ev.Time, events: []Event{ev}})
	if len(list) > maxPartialsPerKey {
		list = list[len(list)-maxPartialsPerKey:]
	}
	byKey[key] = list
	return nil
}

// Sweep drops partials whose maxspan has passed. Call it periodically; Process only skips
// expired partials, it does not free them.
func (e *Engine) Sweep(now time.Time) {
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
