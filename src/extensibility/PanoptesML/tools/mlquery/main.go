//go:build windows

// PanoptesMLQuery scores files with PanoptesML.dll and prints the result, for testing the module
// and its model without the service or a container.
//
// It loads the DLL and calls its test export PanoMlScoreFile, which runs the same feature
// extraction and model as a container scan but returns the result instead of sending it to the
// service. Files are only read, never run.
//
//	PanoptesMLQuery C:\Windows\System32\notepad.exe
//	PanoptesMLQuery -features -r C:\samples
//	PanoptesMLQuery -json -r C:\samples > features.jsonl
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// Must match PANO_ML_FEATURE_VERSION and FEATURE_COUNT in PanoptesML.h; PanoMlTestResult's size
// depends on them, and the DLL refuses a struct of any other size
const (
	featureVersion = 1
	featureCount   = 278
	histogramSize  = 256 // the byte histogram: features 0..255
)

// PanoMlScoreFile results
const (
	resultOK      = 0
	resultFailed  = -1
	resultNoModel = -2
)

// errMismatch means the DLL and this tool were built from different sources; no file can be scored
var errMismatch = errors.New("PanoptesML.dll does not match this tool")

// scoreResult mirrors PanoMlTestResult. Every field is 4-byte aligned, so the Go layout is the
// same as the C one, with no padding
type scoreResult struct {
	StructSize     uint32
	FeatureVersion int32
	FeatureCount   int32
	IsPe           int32
	Malicious      int32
	Score          float32
	Threshold      float32
	Features       [featureCount]float32
	Model          [128]byte
	Error          [512]byte
}

func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

type module struct {
	scoreFile   *syscall.Proc
	featureName *syscall.Proc
}

// routeDLLOutputToStderr points the process's standard-output handle at stderr, so whatever the
// DLL prints (Debug builds of ONNX Runtime's cpuinfo log to stdout) can't mix with the results
// and -json stays parseable. The DLL's C runtime reads the handle when it loads, so this must run
// before LoadDLL. os.Stdout keeps the handle Go read at startup, so the results still go to the
// real stdout
func routeDLLOutputToStderr() {
	const stdOutputHandle = 0xFFFFFFF5 // STD_OUTPUT_HANDLE, (DWORD)-11
	setStdHandle := syscall.NewLazyDLL("kernel32.dll").NewProc("SetStdHandle")
	setStdHandle.Call(stdOutputHandle, uintptr(syscall.Stderr))
}

func loadModule(path string) (*module, error) {
	routeDLLOutputToStderr()
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}
	m := &module{}
	if m.scoreFile, err = dll.FindProc("PanoMlScoreFile"); err != nil {
		return nil, fmt.Errorf("%s has no PanoMlScoreFile export; rebuild PanoptesML: %w", path, err)
	}
	if m.featureName, err = dll.FindProc("PanoMlFeatureName"); err != nil {
		return nil, fmt.Errorf("%s has no PanoMlFeatureName export; rebuild PanoptesML: %w", path, err)
	}
	return m, nil
}

// score returns the result even on resultNoModel, where the features are still valid
func (m *module) score(path string) (*scoreResult, int32, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, resultFailed, err
	}
	r := &scoreResult{}
	r.StructSize = uint32(unsafe.Sizeof(*r))
	ret, _, _ := m.scoreFile.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(r)))
	code := int32(ret)
	if code == resultFailed && r.FeatureCount == 0 {
		// Nothing was written: the DLL has another PanoMlTestResult layout
		return nil, code, fmt.Errorf("%w: it uses a different result layout (another feature version?); rebuild PanoptesMLQuery from the same sources", errMismatch)
	}
	if r.FeatureVersion != featureVersion || r.FeatureCount != featureCount {
		return nil, resultFailed, fmt.Errorf("%w: it has feature version %d (%d features); this tool expects %d (%d)",
			errMismatch, r.FeatureVersion, r.FeatureCount, featureVersion, featureCount)
	}
	if code != resultOK {
		return r, code, errors.New(cString(r.Error[:]))
	}
	return r, code, nil
}

func (m *module) featureNames() ([]string, error) {
	names := make([]string, featureCount)
	buffer := make([]byte, 64)
	for i := range names {
		n, _, _ := m.featureName.Call(uintptr(i), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if int32(n) < 0 {
			return nil, fmt.Errorf("PanoptesML.dll has no name for feature %d", i)
		}
		names[i] = string(buffer[:n])
	}
	return names, nil
}

// defaultDLL looks for the module where the build and the package put it: ext\ next to this exe
func defaultDLL() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, candidate := range []string{
		filepath.Join(dir, "ext", "PanoptesML.dll"),
		filepath.Join(dir, "PanoptesML.dll"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// collect expands folders into the files in them (and below them with recurse). A path that
// can't be read is reported and counted in missing; the rest are still scanned
func collect(args []string, recurse bool) (files []string, missing int, err error) {
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", arg, err)
			missing++
			continue
		}
		if !info.IsDir() {
			files = append(files, arg)
			continue
		}
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
				return nil
			}
			if d.IsDir() {
				if path != arg && !recurse {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, missing, err
		}
	}
	return files, missing, nil
}

// jsonResult is one line of -json output: every feature in model order, for building datasets
type jsonResult struct {
	Path           string    `json:"path"`
	Score          *float32  `json:"score"` // null when the model didn't load
	Threshold      float32   `json:"threshold"`
	Malicious      bool      `json:"malicious"`
	IsPe           bool      `json:"is_pe"`
	Model          string    `json:"model,omitempty"`
	FeatureVersion int32     `json:"feature_version"`
	Features       []float32 `json:"features"`
	Error          string    `json:"error,omitempty"`
}

func printText(path string, r *scoreResult, code int32, names []string, all bool) {
	fmt.Println(path)
	if code == resultOK {
		verdict := "benign"
		if r.Malicious != 0 {
			verdict = "MALICIOUS"
		} else if r.IsPe == 0 {
			verdict = "no verdict" // the model only scores PE files; the score is shown for testing
		}
		kind := "not a PE"
		if r.IsPe != 0 {
			kind = "PE"
		}
		fmt.Printf("  score %.4f  %s (threshold %.2f)  %s  model %s\n",
			r.Score, verdict, r.Threshold, kind, cString(r.Model[:]))
	}
	if names == nil {
		return
	}
	start := histogramSize
	if all {
		start = 0
	}
	for i := start; i < featureCount; i++ {
		// The histogram is mostly zeros; -all still skips them to keep the list readable
		if i < histogramSize && r.Features[i] == 0 {
			continue
		}
		fmt.Printf("    %-30s %.6f\n", names[i], r.Features[i])
	}
	if !all {
		printTopBytes(r)
	}
}

// printTopBytes summarizes the byte histogram as its five most frequent byte values
func printTopBytes(r *scoreResult) {
	order := make([]int, histogramSize)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return r.Features[order[a]] > r.Features[order[b]] })
	var top []string
	for _, b := range order[:5] {
		if r.Features[b] > 0 {
			top = append(top, fmt.Sprintf("0x%02x %.1f%%", b, r.Features[b]*100))
		}
	}
	fmt.Printf("    %-30s %s\n", "most frequent bytes", strings.Join(top, ", "))
}

func main() {
	dllPath := flag.String("dll", "", `PanoptesML.dll to load (default: ext\PanoptesML.dll next to this exe). model.onnx is loaded from the DLL's folder`)
	features := flag.Bool("features", false, "also print the named features (the byte histogram is summarized)")
	all := flag.Bool("all", false, "with -features, print the non-zero byte-histogram values too")
	asJSON := flag.Bool("json", false, "print one JSON object per file, with every feature in model order")
	recurse := flag.Bool("r", false, "scan folders recursively")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] <file or folder>...\n\nScores files with PanoptesML.dll. Files are only read, never run.\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if *dllPath == "" {
		*dllPath = defaultDLL()
		if *dllPath == "" {
			fmt.Fprintln(os.Stderr, `PanoptesML.dll not found in ext\ next to this exe; pass -dll`)
			os.Exit(2)
		}
	}
	absolute, err := filepath.Abs(*dllPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	m, err := loadModule(absolute)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var names []string
	if *features && !*asJSON {
		if names, err = m.featureNames(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	files, missing, err := collect(flag.Args(), *recurse)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	encoder := json.NewEncoder(os.Stdout)
	failed := missing
	for _, file := range files {
		r, code, err := m.score(file)
		if r == nil {
			// Nothing usable: a layout or version mismatch stops the run, a file error doesn't
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			if errors.Is(err, errMismatch) {
				os.Exit(2)
			}
			failed++
			continue
		}
		if code == resultFailed {
			failed++
			if !*asJSON {
				fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
				continue
			}
		}
		if code == resultNoModel {
			failed++
			if !*asJSON {
				fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			}
		}

		if *asJSON {
			line := jsonResult{
				Path:           file,
				Threshold:      r.Threshold,
				Malicious:      r.Malicious != 0,
				IsPe:           r.IsPe != 0,
				Model:          cString(r.Model[:]),
				FeatureVersion: r.FeatureVersion,
			}
			if code == resultOK {
				score := r.Score
				line.Score = &score
			}
			if code != resultFailed {
				line.Features = r.Features[:]
			}
			if err != nil {
				line.Error = err.Error()
			}
			if err := encoder.Encode(line); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			continue
		}
		printText(file, r, code, names, *all)
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d files could not be scored\n", failed, len(files)+missing)
		os.Exit(1)
	}
}
