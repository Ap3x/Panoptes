// Package source produces engine events, either live from PanoptesService over gRPC or by
// replaying a pano.log NDJSON file (for writing and testing rules offline).
package source

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/sys/windows/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Ap3x/Panoptes/detector/src/engine"
	"github.com/Ap3x/Panoptes/detector/src/pb"
)

// ---- Replay ----

// The log's "Time" format (FormatSystemTime in src/service/src/utils.cpp), in UTC
const logTimeLayout = "2006/01/02 15:04:05"

// Replay sends each JSON line of an NDJSON log to out, then closes it. Lines that are not JSON
// objects are skipped. The log's one-second time resolution makes maxspan approximate.
func Replay(path string, out chan<- engine.Event) error {
	defer close(out)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var line uint64
	for sc.Scan() {
		line++
		var fields map[string]any
		if json.Unmarshal(sc.Bytes(), &fields) != nil {
			continue
		}
		ts, _ := fields["Time"].(string)
		t, err := time.Parse(logTimeLayout, ts)
		if err != nil {
			continue
		}
		out <- engine.Event{Seq: line, Time: t, Fields: fields}
	}
	return sc.Err()
}

// ---- Live ----

// Service is a connection to PanoptesService.
type Service struct {
	conn   *grpc.ClientConn
	client pb.PanoptesServiceClient
}

// Connect dials the service on the port it publishes in SOFTWARE\Panoptes\SRV_PORT, the same
// lookup the containers do (src/container/src/container.cpp). Debug builds of the service use
// HKCU instead of HKLM (PANOPTES_REG_ROOT in service_constants.h).
func Connect(debugBuild bool) (*Service, error) {
	root := registry.LOCAL_MACHINE
	if debugBuild {
		root = registry.CURRENT_USER
	}
	k, err := registry.OpenKey(root, `SOFTWARE\Panoptes`, registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open SOFTWARE\\Panoptes: %w", err)
	}
	defer k.Close()
	port, _, err := k.GetIntegerValue("SRV_PORT")
	if err != nil {
		return nil, fmt.Errorf("read SRV_PORT: %w", err)
	}

	conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", port),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Service{conn: conn, client: pb.NewPanoptesServiceClient(conn)}, nil
}

func (s *Service) Close() error { return s.conn.Close() }

func (s *Service) Report(ctx context.Context, d *pb.Detection) error {
	ack, err := s.client.ReportDetection(ctx, d)
	if err != nil {
		return err
	}
	if ack.GetAckType() != pb.AckType_SUCCESS {
		return fmt.Errorf("service rejected detection: %s", ack.GetMessage())
	}
	return nil
}

// Subscribe streams events to out until ctx is cancelled or the stream ends.
func (s *Service) Subscribe(ctx context.Context, hello *pb.DetectorHello, out chan<- engine.Event) error {
	stream, err := s.client.SubscribeEvents(ctx, hello)
	if err != nil {
		return err
	}
	var last uint64
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if last != 0 && msg.GetSequence() != last+1 {
			log.Printf("stream gap: %d events lost", msg.GetSequence()-last-1)
		}
		last = msg.GetSequence()

		var fields map[string]any
		if err := json.Unmarshal([]byte(msg.GetJson()), &fields); err != nil {
			log.Printf("event %d: %v", msg.GetSequence(), err)
			continue
		}
		select {
		case out <- engine.Event{Seq: msg.GetSequence(), Time: fromFileTime(msg.GetTimestamp()), Fields: fields}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// FILETIME counts 100ns intervals from 1601-01-01; Unix time starts 11644473600s later
func fromFileTime(ft int64) time.Time {
	const epochDiff = 116444736000000000
	return time.Unix(0, (ft-epochDiff)*100).UTC()
}
