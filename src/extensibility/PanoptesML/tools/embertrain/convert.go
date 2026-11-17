package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Splits, from the source file's path: EMBER2024's files are named like
// 2023-09-24_2023-09-30_Win64_train.jsonl, ..._test.jsonl and ..._challenge.jsonl
const (
	splitTrain     = "train"
	splitTest      = "test"
	splitChallenge = "challenge"
)

// splitOf names the split of a source from its name: the file name and the folders between the
// -in folder and it, plus the -in folder's own name (so .../Win64_test/part-000.jsonl is test)
func splitOf(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "challenge"):
		return splitChallenge
	case strings.Contains(lower, "test"):
		return splitTest
	default:
		return splitTrain
	}
}

// source is one file to read and the split its records go to
type source struct {
	path  string
	split string
}

// folders collects repeated -in flags
type folders []string

func (f *folders) String() string     { return strings.Join(*f, ",") }
func (f *folders) Set(v string) error { *f = append(*f, v); return nil }

type line struct {
	split string
	data  []byte
}

type converted struct {
	split string
	s     sample
}

// convertStats counts what was kept and why the rest was skipped
type convertStats struct {
	mu       sync.Mutex
	kept     map[string]int64 // by split
	types    map[string]int64 // file_type of every record seen
	skipped  map[string]int64 // by reason
	lines    atomic.Int64
	started  time.Time
	lastShow time.Time
}

func (c *convertStats) add(m map[string]int64, key string) {
	c.mu.Lock()
	m[key]++
	c.mu.Unlock()
}

// sourceFlags are the flags naming EMBER2024's folders, shared by convert and train
type sourceFlags struct {
	in, trainDirs, testDirs, challengeDirs folders
	types                                  *string
}

func (f *sourceFlags) register(fs *flag.FlagSet) {
	fs.Var(&f.in, "in", "folder with EMBER2024 .jsonl files, searched recursively, split named by its path; repeat for more folders, or list them after the flags")
	fs.Var(&f.trainDirs, "train", "folder whose files are all train, whatever their names (repeatable)")
	fs.Var(&f.testDirs, "test", "folder whose files are all test (repeatable)")
	fs.Var(&f.challengeDirs, "challenge", "folder whose files are all challenge (repeatable)")
	f.types = fs.String("types", "Win32,Win64,Dot_Net", "comma-separated file_type values to keep (case-insensitive); PanoptesML scores PE files")
}

// addArgs adds the folders listed after the flags
func (f *sourceFlags) addArgs(args []string) { f.in = append(f.in, args...) }

func (f *sourceFlags) given() bool {
	return len(f.in)+len(f.trainDirs)+len(f.testDirs)+len(f.challengeDirs) > 0
}

func (f *sourceFlags) keep() map[string]bool {
	keep := map[string]bool{}
	for _, t := range strings.Split(*f.types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			keep[strings.ToLower(t)] = true
		}
	}
	return keep
}

// sources lists the files in every folder given, each with its split
func (f *sourceFlags) sources() ([]source, error) {
	keep := f.keep()
	var sources []source
	for _, group := range []struct {
		dirs  folders
		split string // "" to name it from the path
	}{{f.in, ""}, {f.trainDirs, splitTrain}, {f.testDirs, splitTest}, {f.challengeDirs, splitChallenge}} {
		for _, dir := range group.dirs {
			found, err := findSources(dir, keep, group.split)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				log.Printf("warning: no .jsonl files for %s in %s", *f.types, dir)
			}
			sources = append(sources, found...)
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no .jsonl files for %s in the folders given", *f.types)
	}
	return sources, nil
}

func runConvert(args []string) error {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	var src sourceFlags
	src.register(fs)
	out := fs.String("out", "", "folder to write train.pmlf, test.pmlf and challenge.pmlf to")
	workers := fs.Int("workers", defaultWorkers(), "records parsed in parallel")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: embertrain convert -out <folder> [flags] <folder>...\n\n"+
			"Each source's split comes from its path below the folder given, and that folder's name:\n"+
			"\"test\" or \"challenge\" in it means that split, anything else is train.\n"+
			"train can take the folders itself and converts them when needed; convert alone is optional.\n\n")
		fs.PrintDefaults()
	}
	src.addArgs(parseInterspersed(fs, args))
	if !src.given() || *out == "" {
		fs.Usage()
		return errors.New("convert needs -out and at least one folder")
	}
	sources, err := src.sources()
	if err != nil {
		return err
	}
	return convertSources(sources, src.keep(), *out, *workers)
}

// parseInterspersed parses flags wherever they are among the arguments, as in
// "-data a/ b/ c/ -out model.onnx", where Go's flag package stops at b/. It returns the
// arguments that aren't flags. After "--", everything is an argument
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		fs.Parse(args) // ExitOnError: a bad flag exits with the usage
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(positional, rest...)
		}
		if len(rest) == 0 {
			return positional
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// holdsSources reports whether dir has a .jsonl file anywhere below it
func holdsSources(dir string) bool {
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	found := false
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: keep looking elsewhere
		}
		if d.IsDir() {
			if path != dir && skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isSourceFile(d.Name()) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// manifestName is written beside the .pmlf files when a conversion completes. It records what
// they were made from, so train can tell whether they are current for the folders it's given
const manifestName = "sources.json"

type manifestFile struct {
	Path     string `json:"path"`
	Split    string `json:"split"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"` // Unix seconds
}

type manifest struct {
	FeatureVersion int            `json:"feature_version"`
	Types          []string       `json:"types"`
	Files          []manifestFile `json:"files"`
}

func makeManifest(sources []source, keep map[string]bool) ([]byte, error) {
	m := manifest{FeatureVersion: featureVersion}
	for t := range keep {
		m.Types = append(m.Types, t)
	}
	sort.Strings(m.Types)
	for _, s := range sources {
		info, err := os.Stat(s.path)
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, manifestFile{s.path, s.split, info.Size(), info.ModTime().Unix()})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return json.MarshalIndent(m, "", "  ")
}

// convertedFor reports whether dir holds a finished conversion of exactly these sources: the
// same files, unchanged, with the same splits, types and feature version
func convertedFor(dir string, sources []source, keep map[string]bool) (bool, error) {
	want, err := makeManifest(sources, keep)
	if err != nil {
		return false, err
	}
	have, err := os.ReadFile(filepath.Join(dir, manifestName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if string(have) != string(want) {
		return false, nil
	}
	for _, split := range []string{splitTrain, splitTest, splitChallenge} {
		if _, err := os.Stat(filepath.Join(dir, split+".pmlf")); err != nil {
			return false, nil
		}
	}
	return true, nil
}

// convertSources writes the PanoptesML features of every record in sources to out. The .pmlf
// files are written as .partial and renamed at the end, and the manifest goes last, so an
// interrupted conversion is never mistaken for a finished one
func convertSources(sources []source, keep map[string]bool, out string, workers int) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(out, manifestName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	manifestData, err := makeManifest(sources, keep)
	if err != nil {
		return err
	}

	writers := map[string]*datasetWriter{}
	for _, split := range []string{splitTrain, splitTest, splitChallenge} {
		w, err := createDataset(filepath.Join(out, split+".pmlf.partial"))
		if err != nil {
			return err
		}
		writers[split] = w
	}

	stats := &convertStats{
		kept: map[string]int64{}, types: map[string]int64{}, skipped: map[string]int64{},
		started: time.Now(), lastShow: time.Now(),
	}
	lines := make(chan line, 1024)
	results := make(chan converted, 1024)

	// Readers -> parsers -> one writer. Records are independent, so their order doesn't matter
	var parsers sync.WaitGroup
	for range workers {
		parsers.Add(1)
		go func() {
			defer parsers.Done()
			for l := range lines {
				var r emberRecord
				if err := json.Unmarshal(l.data, &r); err != nil {
					stats.add(stats.skipped, "invalid JSON")
					continue
				}
				stats.add(stats.types, r.FileType)
				if !keep[strings.ToLower(r.FileType)] {
					stats.add(stats.skipped, "file_type "+r.FileType)
					continue
				}
				if r.Label == nil || (*r.Label != 0 && *r.Label != 1) {
					stats.add(stats.skipped, "no 0/1 label")
					continue
				}
				var c converted
				c.split = l.split
				c.s.Label = float32(*r.Label)
				c.s.Week = float32(r.WeekID)
				if !toFeatures(&r, &c.s.Features) {
					// PanoptesML only gets a full feature vector for parsable PEs; a model
					// trained on records the C++ wouldn't parse learns nothing useful
					stats.add(stats.skipped, "not a parsable PE")
					continue
				}
				results <- c
			}
		}()
	}
	var writeErr error
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for c := range results {
			if writeErr == nil {
				writeErr = writers[c.split].Write(&c.s)
			}
			stats.add(stats.kept, c.split)
		}
	}()

	var readErr error
	for _, src := range sources {
		log.Printf("reading %s (%s)", src.path, src.split)
		if err := readSource(src, lines, stats); err != nil {
			readErr = fmt.Errorf("%s: %w", src.path, err)
			break
		}
	}
	close(lines)
	parsers.Wait()
	close(results)
	<-writerDone

	for split, w := range writers {
		if err := w.Close(); err != nil && writeErr == nil {
			writeErr = fmt.Errorf("%s: %w", split, err)
		}
	}
	stats.report()
	if readErr != nil {
		return readErr
	}
	if writeErr != nil {
		return writeErr
	}
	for _, split := range []string{splitTrain, splitTest, splitChallenge} {
		if err := os.Rename(filepath.Join(out, split+".pmlf.partial"), filepath.Join(out, split+".pmlf")); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(out, manifestName), manifestData, 0o644)
}

// emberTypes are EMBER2024's file_type values, lower-case, as they appear in its file and folder
// names: Win64_train, 2023-09-24_2023-09-30_Win64_train.jsonl
var emberTypes = []string{"win32", "win64", "dot_net", "apk", "elf", "pdf"}

// skippedType reports whether a path names a file type that isn't kept, as in
// ..._APK_train.jsonl or a PDF_test folder, so those files aren't read at all. Records are still
// filtered by their own file_type; this only saves reading files that hold nothing to keep. A
// name without a known type is never skipped
func skippedType(components []string, keep map[string]bool) bool {
	for _, c := range components {
		c = strings.TrimSuffix(c, filepath.Ext(c))
		for _, suffix := range []string{"_train", "_test"} {
			stem, ok := strings.CutSuffix(c, suffix)
			if !ok {
				continue
			}
			for _, typ := range emberTypes {
				if (stem == typ || strings.HasSuffix(stem, "_"+typ)) && !keep[typ] {
					return true
				}
			}
		}
	}
	return false
}

// isSourceFile reports whether a file is one to read: a .jsonl, but not a hidden or metadata
// file such as macOS's ._name.jsonl
func isSourceFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".jsonl") && !strings.HasPrefix(name, ".")
}

// skippedDir reports folders that hold no data: hidden ones and Synology's @eaDir, #recycle
func skippedDir(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "#")
}

// findSources lists the .jsonl files under dir with the split of each: forcedSplit, or when
// that's empty, the split their path names
func findSources(dir string, keep map[string]bool, forcedSplit string) ([]source, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// WalkDir doesn't follow a symbolic link, even as the folder given (common on NAS shares)
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if info, err := os.Stat(root); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	var sources []source
	var seen, typeSkipped int
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isSourceFile(d.Name()) {
			return nil
		}
		seen++
		// What names the split and type: the folder given, and the path below it
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		named := strings.ToLower(filepath.Join(filepath.Base(root), rel))
		split := forcedSplit
		if split == "" {
			split = splitOf(named)
		}
		if split != splitChallenge && skippedType(strings.Split(named, string(filepath.Separator)), keep) {
			typeSkipped++
			return nil
		}
		sources = append(sources, source{path: path, split: split})
		return nil
	})
	log.Printf("%s: %d .jsonl files, %d to read, %d skipped for their file type in the name", dir, seen, len(sources), typeSkipped)
	sort.Slice(sources, func(i, j int) bool { return sources[i].path < sources[j].path })
	return sources, err
}

// readSource sends every line of a .jsonl file to lines
func readSource(src source, lines chan<- line, stats *convertStats) error {
	f, err := os.Open(src.path)
	if err != nil {
		return err
	}
	defer f.Close()
	return readLines(f, src.split, lines, stats)
}

func readLines(r io.Reader, split string, lines chan<- line, stats *convertStats) error {
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		// ReadBytes has no line length limit: some records hold long string and capa lists
		data, err := br.ReadBytes('\n')
		if len(data) > 1 {
			lines <- line{split: split, data: data}
			if n := stats.lines.Add(1); n%100000 == 0 {
				elapsed := time.Since(stats.started).Seconds()
				log.Printf("%d records read (%.0f/s)", n, float64(n)/elapsed)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (c *convertStats) report() {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("done in %s: %d records read", time.Since(c.started).Round(time.Second), c.lines.Load())
	for _, split := range []string{splitTrain, splitTest, splitChallenge} {
		log.Printf("  kept %-9s %d", split, c.kept[split])
	}
	for _, m := range []struct {
		title  string
		counts map[string]int64
	}{{"file types seen", c.types}, {"skipped", c.skipped}} {
		keys := make([]string, 0, len(m.counts))
		for k := range m.counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			log.Printf("  %s: %-28q %d", m.title, k, m.counts[k])
		}
	}
}
