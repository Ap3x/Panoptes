package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Ap3x/Panoptes/mltools/internal/onnx"
)

// runEval scores EMBER2024 records with a model.onnx, as PanoptesML would score the files they
// describe, and reports how well it separates them: AUC, and what PanoptesML's fixed 0.5
// threshold detects and flags, overall and by week. It runs the model in Go (internal/onnx);
// -check compares that with PanoptesML.dll's scores, from PanoptesMLQuery -json
func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	var src sourceFlags
	src.register(fs)
	var dataFlags folders
	fs.Var(&dataFlags, "data", "EMBER2024 folder of .jsonl files (repeatable, or list folders after the flags), or a folder already converted (train.pmlf, test.pmlf, challenge.pmlf)")
	modelPath := fs.String("model", "model.onnx", "model to evaluate")
	cache := fs.String("cache", "", "folder to convert the records into and reuse on later runs (default: a temporary folder, deleted afterwards)")
	check := fs.String("check", "", "PanoptesMLQuery -json output: score its feature vectors here and compare with the DLL's scores, instead of evaluating")
	workers := fs.Int("workers", defaultWorkers(), "CPU threads")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: embertrain eval -model model.onnx -data <EMBER folder>... [flags]\n"+
			"   or: embertrain eval -model model.onnx -check <PanoptesMLQuery -json output>\n\n")
		fs.PrintDefaults()
	}
	src.addArgs(parseInterspersed(fs, args))

	data, err := os.ReadFile(*modelPath)
	if err != nil {
		return err
	}
	model, err := onnx.Decode(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *modelPath, err)
	}
	if *check != "" {
		return checkAgainstDLL(model, *check)
	}
	if v := model.Metadata["panoptes.feature_version"]; v != "" && v != fmt.Sprint(featureVersion) {
		return fmt.Errorf("%s was trained on feature version %s; these records are converted to version %d", *modelPath, v, featureVersion)
	}
	for _, k := range []string{"trained_on", "threshold", "threshold_baked", "target_fpr", "validation_auc", "validation_tpr", "validation_fpr"} {
		if v, ok := model.Metadata["panoptes."+k]; ok {
			log.Printf("model %-16s %s", k, v)
		}
	}

	var converted []string
	for _, dir := range dataFlags {
		if holdsSources(dir) {
			src.addArgs([]string{dir})
		} else {
			converted = append(converted, dir)
		}
	}
	dir := *cache
	switch {
	case len(converted) > 1 || (len(converted) == 1 && src.given()):
		return errors.New("-data: give EMBER folders, or one converted folder")
	case len(converted) == 1:
		dir = converted[0]
	case !src.given():
		fs.Usage()
		return errors.New("eval needs -data")
	default:
		if dir == "" {
			if dir, err = os.MkdirTemp("", "embertrain-eval-"); err != nil {
				return err
			}
			defer os.RemoveAll(dir)
		}
		if err := ensureConverted(&src, dir, false, *workers); err != nil {
			return err
		}
	}

	evaluated := 0
	for _, split := range []string{splitTrain, splitTest, splitChallenge} {
		samples, err := loadAll(filepath.Join(dir, split+".pmlf"))
		if errors.Is(err, os.ErrNotExist) || (err == nil && len(samples) == 0) {
			continue
		}
		if err != nil {
			return err
		}
		scores, err := scoreWith(model, samples, *workers)
		if err != nil {
			return err
		}
		reportEval(split, samples, scores)
		evaluated++
	}
	if evaluated == 0 {
		return errors.New("no records to evaluate")
	}
	return nil
}

func scoreWith(model *onnx.Runner, samples []sample, workers int) ([]float32, error) {
	scores := make([]float32, len(samples))
	var wg sync.WaitGroup
	var firstErr error
	var once sync.Once
	chunk := (len(samples) + workers - 1) / workers
	for lo := 0; lo < len(samples); lo += chunk {
		hi := min(lo+chunk, len(samples))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				s, err := model.Run(samples[i].Features[:])
				if err != nil {
					once.Do(func() { firstErr = err })
					return
				}
				scores[i] = s
			}
		}()
	}
	wg.Wait()
	return scores, firstErr
}

func reportEval(split string, samples []sample, scores []float32) {
	labels := labelsOf(samples)
	r := evaluate(scores, labels, PanoptesThreshold)
	log.Printf("%s: %d records (%d malicious, %d benign)", split, len(samples), r.Malicious, r.Benign)
	log.Printf("  AUC %.5f", r.AUC)
	log.Printf("  at PanoptesML's threshold (%.1f): detects %.2f%% of malicious, flags %.3f%% of benign",
		PanoptesThreshold, 100*r.TPR, 100*r.FPR)
	// What the model could do at other false-positive rates, with thresholds chosen on these
	// records themselves (so optimistic: a deployed threshold is set in advance)
	for _, fpr := range []float64{0.001, 0.01, 0.05} {
		th := thresholdForFPR(scores, labels, fpr)
		at := evaluate(scores, labels, th)
		log.Printf("  at %.1f%% false positives (score >= %.4f): detects %.2f%%", 100*at.FPR, th, 100*at.TPR)
	}

	// By week: how it holds up as the files get further from the training data
	type week struct{ scores, labels []float32 }
	weeks := map[int]*week{}
	for i := range samples {
		w := int(samples[i].Week)
		if weeks[w] == nil {
			weeks[w] = &week{}
		}
		weeks[w].scores = append(weeks[w].scores, scores[i])
		weeks[w].labels = append(weeks[w].labels, labels[i])
	}
	ids := make([]int, 0, len(weeks))
	for w := range weeks {
		ids = append(ids, w)
	}
	sort.Ints(ids)
	if len(ids) > 1 {
		log.Printf("  %-6s %8s %8s %9s %9s", "week", "records", "AUC", "detects", "flags")
		for _, w := range ids {
			wr := evaluate(weeks[w].scores, weeks[w].labels, PanoptesThreshold)
			log.Printf("  %-6d %8d %8.5f %8.2f%% %8.3f%%", w, len(weeks[w].scores), wr.AUC, 100*wr.TPR, 100*wr.FPR)
		}
	}
}

// PanoptesThreshold is PANO_ML_THRESHOLD: PanoptesML reports a file as malicious at or above it
const PanoptesThreshold = 0.5

// checkAgainstDLL scores the feature vectors in PanoptesMLQuery -json output with the model here,
// and compares with the scores the DLL gave the same vectors
func checkAgainstDLL(model *onnx.Runner, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var n, verdicts int
	var worst float64
	var worstPath string
	for sc.Scan() {
		var q struct {
			Path      string    `json:"path"`
			Score     float32   `json:"score"`
			Malicious bool      `json:"malicious"`
			Features  []float32 `json:"features"`
		}
		if err := json.Unmarshal(sc.Bytes(), &q); err != nil || len(q.Features) != featureCount {
			continue // an error line, or not -json output
		}
		s, err := model.Run(q.Features)
		if err != nil {
			return err
		}
		n++
		if d := math.Abs(float64(s - q.Score)); d > worst {
			worst, worstPath = d, q.Path
		}
		if (s >= PanoptesThreshold) != q.Malicious {
			verdicts++
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s: no PanoptesMLQuery -json lines", path)
	}
	log.Printf("%d files: largest difference from the DLL's score %.2g (%s); %d different verdicts", n, worst, worstPath, verdicts)
	if worst > 1e-4 || verdicts > 0 {
		return errors.New("the scores differ from the DLL's")
	}
	return nil
}
