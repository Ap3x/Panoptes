package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// The converted datasets (train.pmlf, test.pmlf, challenge.pmlf): a fixed header, then fixed-size
// records, all little-endian. A fixed record size lets training read any block of records by
// offset, so an epoch can visit the file in a random order without loading it into memory.
//
//	header: "PMLF", format version, feature version, feature count (uint32 each), record count (uint64)
//	record: featureCount float32 features, label float32 (0 or 1), week float32
const (
	datasetMagic   = "PMLF"
	datasetVersion = 1
	headerSize     = 4 + 4 + 4 + 4 + 8
	recordFloats   = featureCount + 2
	recordSize     = recordFloats * 4
)

type sample struct {
	Features [featureCount]float32
	Label    float32
	Week     float32
}

func (s *sample) encode(b []byte) {
	for i, v := range s.Features {
		binary.LittleEndian.PutUint32(b[4*i:], math.Float32bits(v))
	}
	binary.LittleEndian.PutUint32(b[4*featureCount:], math.Float32bits(s.Label))
	binary.LittleEndian.PutUint32(b[4*featureCount+4:], math.Float32bits(s.Week))
}

func (s *sample) decode(b []byte) {
	for i := range s.Features {
		s.Features[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
	}
	s.Label = math.Float32frombits(binary.LittleEndian.Uint32(b[4*featureCount:]))
	s.Week = math.Float32frombits(binary.LittleEndian.Uint32(b[4*featureCount+4:]))
}

// datasetWriter appends samples and writes the record count into the header on Close
type datasetWriter struct {
	file   *os.File
	buf    *bufio.Writer
	count  uint64
	record [recordSize]byte
}

func createDataset(path string) (*datasetWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &datasetWriter{file: file, buf: bufio.NewWriterSize(file, 4<<20)}
	if err := w.writeHeader(); err != nil {
		file.Close()
		return nil, err
	}
	return w, nil
}

func (w *datasetWriter) writeHeader() error {
	var h [headerSize]byte
	copy(h[0:4], datasetMagic)
	binary.LittleEndian.PutUint32(h[4:], datasetVersion)
	binary.LittleEndian.PutUint32(h[8:], featureVersion)
	binary.LittleEndian.PutUint32(h[12:], featureCount)
	binary.LittleEndian.PutUint64(h[16:], w.count)
	_, err := w.buf.Write(h[:])
	return err
}

func (w *datasetWriter) Write(s *sample) error {
	s.encode(w.record[:])
	w.count++
	_, err := w.buf.Write(w.record[:])
	return err
}

func (w *datasetWriter) Close() error {
	if err := w.buf.Flush(); err != nil {
		w.file.Close()
		return err
	}
	// Rewrite the header now that the count is known
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		w.file.Close()
		return err
	}
	w.buf.Reset(w.file)
	if err := w.writeHeader(); err != nil {
		w.file.Close()
		return err
	}
	if err := w.buf.Flush(); err != nil {
		w.file.Close()
		return err
	}
	return w.file.Close()
}

type dataset struct {
	file  *os.File
	Count int64
}

func openDataset(path string) (*dataset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var h [headerSize]byte
	if _, err := io.ReadFull(file, h[:]); err != nil {
		file.Close()
		return nil, fmt.Errorf("%s: reading the header: %w", path, err)
	}
	if string(h[0:4]) != datasetMagic || binary.LittleEndian.Uint32(h[4:]) != datasetVersion {
		file.Close()
		return nil, fmt.Errorf("%s is not an embertrain dataset (format %d)", path, datasetVersion)
	}
	if fv, fc := binary.LittleEndian.Uint32(h[8:]), binary.LittleEndian.Uint32(h[12:]); fv != featureVersion || fc != featureCount {
		file.Close()
		return nil, fmt.Errorf("%s has feature version %d (%d features); this build uses %d (%d). Run convert again",
			path, fv, fc, featureVersion, featureCount)
	}
	d := &dataset{file: file, Count: int64(binary.LittleEndian.Uint64(h[16:]))}
	if info, err := file.Stat(); err == nil && info.Size() < headerSize+d.Count*recordSize {
		file.Close()
		return nil, fmt.Errorf("%s is truncated: its header says %d records", path, d.Count)
	}
	return d, nil
}

// ReadRange decodes records [first, first+len(out)) into out
func (d *dataset) ReadRange(first int64, out []sample, buf []byte) error {
	n := len(out)
	if cap(buf) < n*recordSize {
		return errors.New("ReadRange: buffer too small")
	}
	buf = buf[:n*recordSize]
	if _, err := d.file.ReadAt(buf, headerSize+first*recordSize); err != nil {
		return err
	}
	for i := range out {
		out[i].decode(buf[i*recordSize:])
	}
	return nil
}

// ForEach reads every record in order, in blocks, and calls fn with each block
func (d *dataset) ForEach(fn func([]sample)) error {
	const block = 4096
	samples := make([]sample, block)
	buf := make([]byte, block*recordSize)
	for first := int64(0); first < d.Count; first += block {
		n := int(min(int64(block), d.Count-first))
		if err := d.ReadRange(first, samples[:n], buf); err != nil {
			return err
		}
		fn(samples[:n])
	}
	return nil
}

func (d *dataset) Close() error { return d.file.Close() }
