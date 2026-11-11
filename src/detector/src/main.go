// PanoptesDetector evaluates behavioral rules (rules/*.yaml) over Panoptes events.
//
//	PanoptesDetector -rules rules -replay C:\ProgramData\Panoptes\Logs\pano.log   offline, prints matches
//	PanoptesDetector -rules rules                                                 live, reports to the service
//
// Detections are appended as JSON lines to -detection-log (live default:
// %ProgramData%\Panoptes\Logs\detection.log). Replay prints them and writes a file only when the
// flag is given, so replaying a test log does not add to the real detection log.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/Ap3x/Panoptes/detector/src/engine"
	"github.com/Ap3x/Panoptes/detector/src/pb"
	"github.com/Ap3x/Panoptes/detector/src/rules"
	"github.com/Ap3x/Panoptes/detector/src/source"
)

const version = "0.1.0"

func main() {
	rulesDir := flag.String("rules", "rules", "directory of rule YAML files")
	replay := flag.String("replay", "", "replay an NDJSON log instead of connecting to the service")
	debugSvc := flag.Bool("debug-service", false, "find the service port under HKCU (debug builds)")
	reorderDelay := flag.Duration("reorder", 2*time.Second,
		"hold events this long to put driver and hook events back in time order (0 disables)")
	detectionLogPath := flag.String("detection-log", defaultDetectionLog(),
		"file detections are appended to, one JSON object per line")
	flag.Parse()
	logExplicit := false
	flag.Visit(func(f *flag.Flag) { logExplicit = logExplicit || f.Name == "detection-log" })

	rs, err := rules.LoadDir(*rulesDir)
	if err != nil {
		log.Fatalf("loading rules: %v", err)
	}
	log.Printf("loaded %d rules", len(rs))
	eng := engine.New(rs)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	events := make(chan engine.Event, 4096)
	reorder := engine.NewReorderer(*reorderDelay)

	var dlog *detectionLog
	if *replay == "" || logExplicit {
		if dlog, err = openDetectionLog(*detectionLogPath); err != nil {
			// Keep detecting and reporting to the service; only the file record is lost
			log.Printf("detection log disabled: %v", err)
		} else {
			log.Printf("writing detections to %s", *detectionLogPath)
		}
	}
	defer dlog.Close()

	if *replay != "" {
		go func() {
			if err := source.Replay(*replay, events); err != nil {
				log.Printf("replay: %v", err)
			}
		}()
		enc := json.NewEncoder(os.Stdout)
		process := func(evs []engine.Event) {
			for _, ev := range evs {
				for _, m := range eng.Process(ev) {
					enc.Encode(summary(m))
					if dlog != nil {
						if err := dlog.Write(m, time.Now(), nil); err != nil {
							log.Printf("detection log: %v", err)
						}
					}
				}
				eng.Sweep(ev.Time) // replay runs on log time, not wall time
			}
		}
		for ev := range events {
			reorder.Push(ev)
			process(reorder.Pop(reorder.ReplayWatermark()))
		}
		process(reorder.Flush())
		if reorder.Late > 0 {
			log.Printf("%d events arrived more than %s late and were processed out of order", reorder.Late, reorder.Delay)
		}
		return
	}

	runLive(ctx, eng, reorder, events, *debugSvc, dlog)
}

func runLive(ctx context.Context, eng *engine.Engine, reorder *engine.Reorderer, events chan engine.Event,
	debugSvc bool, dlog *detectionLog) {
	// The service restarts independently, so keep reconnecting
	go func() {
		defer close(events)
		backoff := time.Second
		for ctx.Err() == nil {
			svc, err := source.Connect(debugSvc)
			if err == nil {
				err = svc.Subscribe(ctx, &pb.DetectorHello{Version: version}, events)
				svc.Close()
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("event stream: %v; retrying in %s", err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 30*time.Second)
		}
	}()

	// Held events are released on this tick, so it bounds the extra latency beyond the delay
	release := time.NewTicker(100 * time.Millisecond)
	defer release.Stop()
	sweep := time.NewTicker(5 * time.Second)
	defer sweep.Stop()

	// Reports go out from their own goroutine: a slow or unreachable service must not hold up
	// matching (each report can take up to its timeout). It also writes detection.log, after
	// the report, so the record says whether the service accepted it
	matches := make(chan engine.Match, maxPendingReports)
	defer close(matches)
	go func() {
		var reporter *source.Service // separate connection for reports, opened lazily
		for m := range matches {
			reported := report(ctx, &reporter, debugSvc, m)
			writeDetection(dlog, m, reported)
		}
	}()

	var lateReported uint64
	for {
		var ready []engine.Event
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			reorder.Push(ev)
			continue
		case now := <-release.C:
			ready = reorder.Pop(reorder.LiveWatermark(now))
			if reorder.Late != lateReported {
				log.Printf("%d events arrived more than %s late; consider a larger -reorder", reorder.Late-lateReported, reorder.Delay)
				lateReported = reorder.Late
			}
		case now := <-sweep.C:
			// The engine has only seen events up to the watermark, so that is its "now"; sweeping
			// with wall time would expire partials whose next step is still being held
			eng.Sweep(reorder.LiveWatermark(now))
			continue
		}

		for _, ev := range ready {
			for _, m := range eng.Process(ev) {
				log.Printf("detection: %s", m.Rule.Name)
				select {
				case matches <- m:
				default:
					// The service is far behind; keep the record rather than block matching
					log.Printf("report queue full; %s not reported", m.Rule.Name)
					writeDetection(dlog, m, false)
				}
			}
		}
	}
}

// Detections waiting to be reported before new ones are only written to detection.log
const maxPendingReports = 256

func writeDetection(dlog *detectionLog, m engine.Match, reported bool) {
	if dlog == nil {
		return
	}
	if err := dlog.Write(m, time.Now(), &reported); err != nil {
		log.Printf("detection log: %v", err)
	}
}

// report sends the detection to the service over *reporter, connecting first if needed and
// dropping the connection on failure so the next detection reconnects. Returns whether the
// service accepted it.
func report(ctx context.Context, reporter **source.Service, debugSvc bool, m engine.Match) bool {
	if *reporter == nil {
		if *reporter, _ = source.Connect(debugSvc); *reporter == nil {
			log.Printf("cannot report %s: service unavailable", m.Rule.Name)
			return false
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := (*reporter).Report(rctx, toProto(m)); err != nil {
		log.Printf("report %s: %v", m.Rule.Name, err)
		(*reporter).Close()
		*reporter = nil
		return false
	}
	return true
}

func toProto(m engine.Match) *pb.Detection {
	d := &pb.Detection{
		Rule:        m.Rule.Name,
		Description: m.Rule.Description,
		Severity:    severity(m.Rule.Severity),
		Action:      action(m.Rule.Action),
	}
	if pid, ok := m.TargetPID(); ok {
		d.ProcessId = pid
	}
	last := m.Events[len(m.Events)-1].Fields
	if img, ok := last["Image"].(string); ok {
		d.ImagePath = img
	}
	for _, ev := range m.Events {
		d.EventSequences = append(d.EventSequences, ev.Seq)
	}
	// The service checks the process existed by then, so a reused PID is never acted on
	d.Timestamp = toFileTime(m.Events[len(m.Events)-1].Time)
	return d
}

// toFileTime converts to 100ns intervals since 1601-01-01 UTC, the inverse of source.fromFileTime
func toFileTime(t time.Time) int64 {
	const epochDiff = 116444736000000000
	return t.UnixNano()/100 + epochDiff
}

func summary(m engine.Match) map[string]any {
	evs := make([]map[string]any, len(m.Events))
	for i, ev := range m.Events {
		evs[i] = ev.Fields
	}
	pid, _ := m.TargetPID()
	return map[string]any{"Rule": m.Rule.Name, "Description": m.Rule.Description,
		"Severity": m.Rule.Severity, "Action": m.Rule.Action, "Key": m.Key, "TargetPID": pid,
		"Events": evs}
}

func severity(s rules.Severity) pb.DetectionSeverity {
	switch s {
	case "medium":
		return pb.DetectionSeverity_DETECTION_SEVERITY_MEDIUM
	case "high":
		return pb.DetectionSeverity_DETECTION_SEVERITY_HIGH
	case "critical":
		return pb.DetectionSeverity_DETECTION_SEVERITY_CRITICAL
	}
	return pb.DetectionSeverity_DETECTION_SEVERITY_LOW
}

func action(a rules.Action) pb.DetectionAction {
	switch a {
	case rules.ActionKill:
		return pb.DetectionAction_DETECTION_ACTION_KILL
	case rules.ActionQuarantine:
		return pb.DetectionAction_DETECTION_ACTION_QUARANTINE
	}
	return pb.DetectionAction_DETECTION_ACTION_ALERT
}
