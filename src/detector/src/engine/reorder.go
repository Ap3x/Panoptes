package engine

import (
	"container/heap"
	"time"
)

// Reorderer puts events back in time order before they reach the Engine.
//
// The service gets events from two pipelines with different latency: driver events come straight
// from the driver's queue, while hook events go through an ETW real-time session, which delivers
// buffers about once a second. A hook event can therefore arrive after a driver event that
// happened later (e.g. the ProcessTerminated of the process it injected into). The Reorderer holds
// each event until the watermark, a point in time before which no more events are expected,
// has passed it, then releases events sorted by (Time, Seq).
//
// An event older than one already released (it arrived more than the delay late) is released on
// the next Pop, out of order, and counted in Late.
type Reorderer struct {
	Delay    time.Duration
	Late     uint64
	pending  eventHeap
	released time.Time // Time of the newest released event
	newest   time.Time // Time of the newest pushed event
}

func NewReorderer(delay time.Duration) *Reorderer {
	return &Reorderer{Delay: delay}
}

func (r *Reorderer) Push(ev Event) {
	if !r.released.IsZero() && ev.Time.Before(r.released) {
		r.Late++
	}
	if ev.Time.After(r.newest) {
		r.newest = ev.Time
	}
	heap.Push(&r.pending, ev)
}

// Pop releases, in order, every held event at or before watermark.
func (r *Reorderer) Pop(watermark time.Time) []Event {
	var out []Event
	for r.pending.Len() > 0 && !r.pending[0].Time.After(watermark) {
		ev := heap.Pop(&r.pending).(Event)
		if ev.Time.After(r.released) {
			r.released = ev.Time
		}
		out = append(out, ev)
	}
	return out
}

// LiveWatermark is the watermark for a live stream: events up to Delay before now.
func (r *Reorderer) LiveWatermark(now time.Time) time.Time { return now.Add(-r.Delay) }

// ReplayWatermark is the watermark when replaying a log, where wall time means nothing: events
// up to Delay before the newest event seen so far.
func (r *Reorderer) ReplayWatermark() time.Time { return r.newest.Add(-r.Delay) }

// Flush releases everything still held, in order.
func (r *Reorderer) Flush() []Event {
	var out []Event
	for r.pending.Len() > 0 {
		out = append(out, heap.Pop(&r.pending).(Event))
	}
	return out
}

func (r *Reorderer) Len() int { return r.pending.Len() }

// eventHeap is a min-heap by (Time, Seq). Seq breaks ties, which keeps the arrival order of
// events with the same timestamp (common when replaying a log with one-second times).
type eventHeap []Event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if !h[i].Time.Equal(h[j].Time) {
		return h[i].Time.Before(h[j].Time)
	}
	return h[i].Seq < h[j].Seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(Event)) }
func (h *eventHeap) Pop() any {
	old := *h
	ev := old[len(old)-1]
	*h = old[:len(old)-1]
	return ev
}
