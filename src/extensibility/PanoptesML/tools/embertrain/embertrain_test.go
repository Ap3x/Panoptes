package main

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ap3x/Panoptes/mltools/internal/onnx"
)

func loadSample(t *testing.T) emberRecord {
	t.Helper()
	data, err := os.ReadFile("testdata/win64_benign.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var r emberRecord
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// The expected values are worked out by hand from the record in testdata, with the formulas of
// pe_features.cpp, not with toFeatures
func TestFeaturesOfSampleRecord(t *testing.T) {
	r := loadSample(t)
	var f [featureCount]float32
	if !toFeatures(&r, &f) {
		t.Fatal("the sample is a PE")
	}
	want := map[int]float64{
		fByteHistogram + 0:          52112.0 / 238352,
		fByteHistogram + 255:        7604.0 / 238352,
		fEntropy:                    6.119745990572874 / 8,
		fLogSize:                    0.558210, // log2(238353) / 32
		fIsPe:                       1,
		fIs64Bit:                    1, // magic 523
		fIsDll:                      1,
		fSubsystemGui:               1,
		fSectionCount:               7.0 / 16,
		fSectionEntropyMax:          6.0108744790593684 / 8, // .rdata
		fSectionEntropyMin:          2.7304483519572638 / 8, // .pdata
		fSectionEntropyMean:         27.1199064 / 7 / 8,
		fWritableExecutableSections: 0,
		fEntryOutsideExecutable:     0,        // .text is executable
		fImportedDlls:               0.375,    // log2(7 + 1) / 8
		fImportedFunctions:          0.477327, // log2(52 + 1) / 12
		fHasSignature:               1,
		fHasTls:                     0,
		fHasDebug:                   1,
		fHasRelocations:             1,
		fHasResources:               1,
		fOverlayRatio:               0.08706450963281198,
		fImageToFileRatio:           241664.0 / 238352 / 16,
		fZeroTimestamp:              0,
	}
	for i, v := range want {
		if math.Abs(float64(f[i])-v) > 1e-5 {
			t.Errorf("feature %d = %v, want %v", i, f[i], v)
		}
	}
}

func TestEntryOutsideExecutable(t *testing.T) {
	r := loadSample(t)
	r.Section.Entry = ".rdata" // the entry point in a section that isn't executable
	var f [featureCount]float32
	toFeatures(&r, &f)
	if f[fEntryOutsideExecutable] != 1 {
		t.Error("an entry point in .rdata is outside executable code")
	}
	r.Header.Optional.AddressOfEntrypoint = 0 // a DLL without an entry point
	toFeatures(&r, &f)
	if f[fEntryOutsideExecutable] != 0 {
		t.Error("no entry point is not suspicious")
	}
}

func TestNonPeKeepsByteStatistics(t *testing.T) {
	r := loadSample(t)
	r.General.IsPe = 0
	var f [featureCount]float32
	if toFeatures(&r, &f) {
		t.Fatal("is_pe 0 is not a PE")
	}
	if f[fEntropy] == 0 || f[fByteHistogram] == 0 || f[fIsPe] != 0 || f[fSectionCount] != 0 {
		t.Errorf("want byte statistics only, got entropy %v, histogram[0] %v, is_pe %v, sections %v",
			f[fEntropy], f[fByteHistogram], f[fIsPe], f[fSectionCount])
	}
}

func TestAUCAndThreshold(t *testing.T) {
	scores := []float32{0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9}
	labels := []float32{0, 0, 0, 0, 1, 1, 1, 1}
	if a := auc(scores, labels); a != 1 {
		t.Errorf("separated scores: AUC %v, want 1", a)
	}
	if a := auc([]float32{0.5, 0.5}, []float32{0, 1}); a != 0.5 {
		t.Errorf("tied scores: AUC %v, want 0.5", a)
	}
	// 4 benign; 25% allowed flags one of them: the threshold sits just above the second highest
	th := thresholdForFPR(scores, labels, 0.25)
	r := evaluate(scores, labels, th)
	if r.FPR != 0.25 || r.TPR != 1 {
		t.Errorf("threshold %v: FPR %v TPR %v, want 0.25 and 1", th, r.FPR, r.TPR)
	}
}

func TestSplitsAndTypes(t *testing.T) {
	for name, want := range map[string]string{
		"win64_train/2023-09-24_2023-09-30_win64_train.jsonl": splitTrain,
		"win64_test/2024-09-22_2024-09-28_win64_test.jsonl":   splitTest,
		"ember/2024-09-22_2024-09-28_win64_challenge.jsonl":   splitChallenge,
		"win64_test/part-000.jsonl":                           splitTest,
		"ember/2024-01-01_2024-01-07.jsonl":                   splitTrain,
	} {
		if got := splitOf(name); got != want {
			t.Errorf("splitOf(%q) = %s, want %s", name, got, want)
		}
	}
	keep := map[string]bool{"win32": true, "win64": true, "dot_net": true}
	for path, want := range map[string]bool{
		// EMBER2024's own names: date range, type, split. These were all skipped once, because
		// the type was taken to be everything before _train
		"win64_train/2023-09-24_2023-09-30_win64_train.jsonl":     false,
		"dot_net_train/2023-09-24_2023-09-30_dot_net_train.jsonl": false,
		"win32_test/2024-09-22_2024-09-28_win32_test.jsonl":       false,
		"ember/2023-09-24_2023-09-30_apk_train.jsonl":             true,
		"pdf_test/part-000.jsonl":                                 true,
		"mine_train/part-000.jsonl":                               false, // no known type: read it
	} {
		if got := skippedType(strings.Split(path, "/"), keep); got != want {
			t.Errorf("skippedType(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestFindSourcesEmberNames: folders as extracted from EMBER2024, with a zip beside them (not
// read), a macOS ._ file and a Synology @eaDir folder (not read either)
func TestFindSourcesEmberNames(t *testing.T) {
	dir := t.TempDir()
	keep := map[string]bool{"win32": true, "win64": true, "dot_net": true}
	files := []string{
		"Win64_train/2023-09-24_2023-09-30_Win64_train.jsonl",
		"Win64_train/2023-10-01_2023-10-07_Win64_train.jsonl",
		"Dot_Net_train/2023-09-24_2023-09-30_Dot_Net_train.jsonl",
		"Win64_train/._2023-09-24_2023-09-30_Win64_train.jsonl",
		"Win64_train/@eaDir/2023-09-24_2023-09-30_Win64_train.jsonl",
		"Win64_train.zip",
	}
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("{}\n"), 0o644)
	}
	sources, err := findSources(filepath.Join(dir, "Win64_train")+string(filepath.Separator), keep, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].split != splitTrain {
		t.Errorf("Win64_train: %+v, want its two .jsonl files as train", sources)
	}
	sources, err = findSources(dir, keep, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 3 {
		t.Errorf("all: %d sources, want 3 (no zip, ._ or @eaDir files): %+v", len(sources), sources)
	}
}

// writeSynthetic writes a JSONL file of records derived from the sample, with a signal the model
// can learn: malicious ones get packed-looking sections and a W+X section
func writeSynthetic(t *testing.T, path string, n int, firstWeek, weeks int, rng *rand.Rand) {
	t.Helper()
	base := loadSample(t)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range n {
		r := base
		label := i % 2
		r.Label = &label
		r.WeekID = firstWeek + i%weeks
		r.Section.Sections = append(r.Section.Sections[:0:0], base.Section.Sections...)
		noise := rng.Float64()
		if label == 1 {
			r.Section.Sections[0].Entropy = 7.2 + 0.7*noise
			r.Section.Sections[0].Props = []string{"CNT_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE"}
		} else {
			r.Section.Sections[0].Entropy = 5.0 + 1.5*noise
		}
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
}

// TestConvertAndTrain runs the whole pipeline on synthetic records in EMBER2024's file names:
// two folders, convert, train, export
func TestConvertAndTrain(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewPCG(7, 8))
	trainDir := filepath.Join(dir, "Win64_train")
	os.MkdirAll(trainDir, 0o755)
	writeSynthetic(t, filepath.Join(trainDir, "2023-09-24_2023-09-30_Win64_train.jsonl"), 3000, 0, 52, rng)

	// The test split in a second folder, named only by its files
	testDir := filepath.Join(dir, "other")
	os.MkdirAll(testDir, 0o755)
	writeSynthetic(t, filepath.Join(testDir, "2024-09-22_2024-09-28_Win64_test.jsonl"), 600, 52, 12, rng)

	out := filepath.Join(dir, "data")
	if err := runConvert([]string{"-out", out, trainDir, testDir}); err != nil {
		t.Fatal(err)
	}
	for split, want := range map[string]int64{splitTrain: 3000, splitTest: 600, splitChallenge: 0} {
		d, err := openDataset(filepath.Join(out, split+".pmlf"))
		if err != nil {
			t.Fatal(err)
		}
		if d.Count != want {
			t.Errorf("%s: %d records, want %d", split, d.Count, want)
		}
		d.Close()
	}

	// With EMBERTRAIN_CHECK_FEATURES set to a PanoptesMLQuery -json line, print the score this
	// network gives those features, to compare with what PanoptesML scores using the exported model
	onTrained = func(m *mlp, threshold float32) {
		path := os.Getenv("EMBERTRAIN_CHECK_FEATURES")
		if path == "" {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var q struct{ Features []float32 }
		if err := json.Unmarshal(data, &q); err != nil || len(q.Features) != featureCount {
			t.Fatalf("%s: want one PanoptesMLQuery -json line: %v", path, err)
		}
		var x [featureCount]float32
		copy(x[:], q.Features)
		logit := float64(m.forward(&x, m.newScratch()))
		th := float64(threshold)
		baked := 1 / (1 + math.Exp(-(logit - math.Log(th/(1-th)))))
		t.Logf("CHECK go score %.6f (unshifted %.6f, threshold %.6f)", baked, 1/(1+math.Exp(-logit)), th)
	}
	defer func() { onTrained = nil }()

	model := filepath.Join(dir, "model.onnx")
	if err := runTrain([]string{"-data", out, "-out", model, "-epochs", "4", "-hidden", "16,8", "-batch", "64"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(model)
	if err != nil || info.Size() < 1000 {
		t.Fatalf("model.onnx not written: %v", err)
	}
	// To try the model in PanoptesML: EMBERTRAIN_KEEP_MODEL=<path> go test -run ConvertAndTrain
	if keep := os.Getenv("EMBERTRAIN_KEEP_MODEL"); keep != "" {
		data, _ := os.ReadFile(model)
		if err := os.WriteFile(keep, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTrainFromFolders: train given the JSONL folders converts them the first time, reuses the
// conversion after, and converts again when a source file changes
func TestTrainFromFolders(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewPCG(3, 4))
	trainDir := filepath.Join(dir, "Win64_train")
	testDir := filepath.Join(dir, "Win64_test")
	os.MkdirAll(trainDir, 0o755)
	os.MkdirAll(testDir, 0o755)
	writeSynthetic(t, filepath.Join(trainDir, "part-000.jsonl"), 1000, 0, 52, rng)
	testFile := filepath.Join(testDir, "part-000.jsonl")
	writeSynthetic(t, testFile, 200, 52, 12, rng)

	data := filepath.Join(dir, "data")
	model := filepath.Join(dir, "model.onnx")
	args := []string{"-data", data, "-out", model, "-epochs", "1", "-hidden", "8", "-batch", "64", trainDir, testDir}
	modTime := func() time.Time {
		info, err := os.Stat(filepath.Join(data, splitTrain+".pmlf"))
		if err != nil {
			t.Fatal(err)
		}
		return info.ModTime()
	}

	if err := runTrain(args); err != nil {
		t.Fatal(err)
	}
	first := modTime()
	if _, err := os.Stat(filepath.Join(data, manifestName)); err != nil {
		t.Fatalf("no manifest after converting: %v", err)
	}
	for _, split := range []string{splitTrain, splitTest, splitChallenge} {
		if _, err := os.Stat(filepath.Join(data, split+".pmlf.partial")); err == nil {
			t.Errorf("%s.pmlf.partial left behind", split)
		}
	}

	// Unchanged sources: the conversion is reused
	time.Sleep(10 * time.Millisecond)
	if err := runTrain(args); err != nil {
		t.Fatal(err)
	}
	if !modTime().Equal(first) {
		t.Error("the second run converted again; it should reuse the features")
	}

	// A changed source: converted again, with the new record count
	writeSynthetic(t, testFile, 300, 52, 12, rng)
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(testFile, later, later)
	if err := runTrain(args); err != nil {
		t.Fatal(err)
	}
	d, err := openDataset(filepath.Join(data, splitTest+".pmlf"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Count != 300 {
		t.Errorf("after the test file changed: %d test records, want 300", d.Count)
	}
}

// TestTrainDataFolders: "train -data Win64_train/ Win32_train/ Dot_Net_train/ -out model.onnx",
// folders after one -data and a flag after them; the features go to a data folder beside -out
func TestTrainDataFolders(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewPCG(5, 6))
	var dirs []string
	for _, name := range []string{"Win64_train", "Win32_train", "Dot_Net_train"} {
		d := filepath.Join(dir, name)
		os.MkdirAll(d, 0o755)
		writeSynthetic(t, filepath.Join(d, "2023-09-24_2023-09-30_"+name+".jsonl"), 400, 0, 52, rng)
		dirs = append(dirs, d+string(filepath.Separator))
	}
	model := filepath.Join(dir, "out", "model.onnx")
	os.MkdirAll(filepath.Dir(model), 0o755)
	args := append([]string{"-data"}, dirs...)
	args = append(args, "-out", model, "-epochs", "1", "-hidden", "8")
	if err := runTrain(args); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(model); err != nil {
		t.Fatalf("no model: %v", err)
	}
	d, err := openDataset(filepath.Join(dir, "out", "data", splitTrain+".pmlf"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Count != 1200 {
		t.Errorf("%d training records, want 1200 from the three folders", d.Count)
	}

	// The converted folder given as -data trains without the EMBER folders
	if err := runTrain([]string{"-data", filepath.Join(dir, "out", "data"), "-out", model, "-epochs", "1", "-hidden", "8"}); err != nil {
		t.Fatal(err)
	}
}

// The exported graph must compute what the network does. Without an ONNX runtime here, the
// folded first layer is checked by recomputing it from the exported weights
func TestExportFoldsStandardization(t *testing.T) {
	m := newMLP([]int{4}, 3)
	for i := range m.Mean {
		m.Mean[i] = float32(i%7) * 0.1
		m.Std[i] = 0.5 + float32(i%3)
	}
	var x [featureCount]float32
	for i := range x {
		x[i] = float32(i%11) * 0.05
	}
	s := m.newScratch()
	m.forward(&x, s)

	// First layer from the folded weights, as the ONNX graph computes it
	nIn, nOut := m.Sizes[0], m.Sizes[1]
	for j := 0; j < nOut; j++ {
		b := m.Params[m.bOff[0]+j]
		z := float64(b)
		for i := 0; i < nIn; i++ {
			w := m.Params[m.wOff[0]+j*nIn+i]
			z += float64(w/m.Std[i])*float64(x[i]) - float64(w*m.Mean[i]/m.Std[i])
		}
		if math.Abs(z-float64(s.pre[0][j])) > 1e-3 {
			t.Errorf("unit %d: folded %v, network %v", j, z, s.pre[0][j])
		}
	}
	// The whole exported graph, run by eval's runner: the network's score, shifted by the baked
	// threshold
	runner, err := onnx.Decode(exportONNX(m, 0.7, true, map[string]string{"panoptes.threshold": "0.7"}))
	if err != nil {
		t.Fatal(err)
	}
	if runner.Metadata["panoptes.threshold"] != "0.7" {
		t.Errorf("metadata: %v", runner.Metadata)
	}
	got, err := runner.Run(x[:])
	if err != nil {
		t.Fatal(err)
	}
	logit := float64(m.forward(&x, m.newScratch()))
	want := 1 / (1 + math.Exp(-(logit - math.Log(0.7/0.3))))
	if math.Abs(float64(got)-want) > 1e-5 {
		t.Errorf("exported model scores %v, the network %v", got, want)
	}
}

func TestEval(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewPCG(9, 10))
	trainDir, testDir := filepath.Join(dir, "Win64_train"), filepath.Join(dir, "Win64_test")
	os.MkdirAll(trainDir, 0o755)
	os.MkdirAll(testDir, 0o755)
	writeSynthetic(t, filepath.Join(trainDir, "2023-09-24_2023-09-30_Win64_train.jsonl"), 1000, 0, 52, rng)
	writeSynthetic(t, filepath.Join(testDir, "2024-09-22_2024-09-28_Win64_test.jsonl"), 300, 52, 3, rng)
	model := filepath.Join(dir, "model.onnx")
	if err := runTrain([]string{"-data", trainDir, "-out", model, "-epochs", "2", "-hidden", "8"}); err != nil {
		t.Fatal(err)
	}
	if err := runEval([]string{"-model", model, "-data", testDir}); err != nil {
		t.Fatal(err)
	}
}
