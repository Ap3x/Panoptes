package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func runTrain(args []string) error {
	fs := flag.NewFlagSet("train", flag.ExitOnError)
	var src sourceFlags
	src.register(fs)
	var dataFlags folders
	fs.Var(&dataFlags, "data", "EMBER2024 folder of .jsonl files (split named by its path), or a folder already converted (train.pmlf); takes several: -data Win64_train/ Win32_train/ Dot_Net_train/")
	cache := fs.String("cache", "", "folder the EMBER folders' features are converted into and reused from (default: a data folder next to -out)")
	reconvert := fs.Bool("reconvert", false, "convert the EMBER folders again even when the cache already holds them")
	out := fs.String("out", "model.onnx", "where to write the model")
	hiddenFlag := fs.String("hidden", "128,64", "hidden layer sizes")
	epochs := fs.Int("epochs", 12, "passes over the training set")
	batchSize := fs.Int("batch", 512, "samples per training step")
	lr := fs.Float64("lr", 1e-3, "Adam learning rate")
	decay := fs.Float64("weight-decay", 1e-5, "AdamW weight decay")
	patience := fs.Int("patience", 3, "stop after this many epochs without a better validation AUC")
	validFrom := fs.Int("valid-from-week", 46, "train.pmlf records from this week_id on are held out for validation (early stopping and the threshold); EMBER2024's training weeks are 0-51")
	targetFPR := fs.Float64("target-fpr", 0.01, "false-positive rate the threshold is chosen for, on the validation set")
	calibrate := fs.Bool("bake-threshold", true, "shift the output so the chosen threshold scores 0.5, PanoptesML's fixed threshold (PANO_ML_THRESHOLD)")
	fraction := fs.Float64("sample", 1, "fraction of the training records to train on (0-1], spread evenly over the file, for quick trial runs; validation always uses all its weeks")
	workers := fs.Int("workers", defaultWorkers(), "CPU threads for training")
	seed := fs.Uint64("seed", 1, "random seed (initial weights and shuffling)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: embertrain train -data <EMBER folder>... -out model.onnx [flags]\n"+
			"   or: embertrain train -data <converted folder> -out model.onnx [flags]\n\n"+
			"Given EMBER folders, train converts their JSONL to PanoptesML features in -cache the first\n"+
			"time and reuses that after, until the files, -types or the feature version change.\n"+
			"Flags and folders can come in any order.\n\n")
		fs.PrintDefaults()
	}
	// Folders after -data, or anywhere among the flags, are all folders to read
	src.addArgs(parseInterspersed(fs, args))
	var converted []string
	for _, dir := range dataFlags {
		if holdsSources(dir) {
			src.addArgs([]string{dir})
		} else {
			converted = append(converted, dir)
		}
	}
	data := cache
	switch {
	case len(converted) > 1:
		return fmt.Errorf("-data: %s hold no .jsonl files; only one converted folder can be used", strings.Join(converted, ", "))
	case len(converted) == 1 && *cache != "" && filepath.Clean(*cache) != filepath.Clean(converted[0]):
		return fmt.Errorf("-data %s and -cache %s: give the converted folder once", converted[0], *cache)
	case len(converted) == 1:
		data = &converted[0]
	case *cache == "":
		if !src.given() {
			fs.Usage()
			return errors.New("train needs -data with EMBER folders or a converted one")
		}
		*cache = filepath.Join(filepath.Dir(*out), "data")
	}
	hidden, err := parseSizes(*hiddenFlag)
	if err != nil {
		return err
	}
	if src.given() {
		if err := ensureConverted(&src, *data, *reconvert, *workers); err != nil {
			return err
		}
	}

	train, err := openDataset(filepath.Join(*data, splitTrain+".pmlf"))
	if err != nil {
		return err
	}
	defer train.Close()
	log.Printf("train.pmlf: %d records", train.Count)

	// One pass: the standardization statistics over the training weeks, and the validation set
	// (the last weeks) in memory. Holding out the latest weeks, not a random sample, is closer
	// to how the model is used: on files newer than any it was trained on
	if *fraction <= 0 || *fraction > 1 {
		return fmt.Errorf("-sample must be in (0, 1], not %v", *fraction)
	}
	isValid := func(s *sample) bool { return int(s.Week) >= *validFrom }
	// inSample picks the same records every epoch: a multiplicative hash of the record's index
	inSample := func(index int64) bool {
		return *fraction >= 1 || float64(uint32(uint64(index)*2654435761))/(1<<32) < *fraction
	}
	var mean, m2 [featureCount]float64
	var n float64
	var valid []sample
	var trainCount, trainMalicious int64
	var index int64
	err = train.ForEach(func(block []sample) {
		for i := range block {
			s := &block[i]
			index++
			if isValid(s) {
				valid = append(valid, *s)
				continue
			}
			if !inSample(index - 1) {
				continue
			}
			trainCount++
			if s.Label == 1 {
				trainMalicious++
			}
			n++
			for j, v := range s.Features { // Welford's running mean and variance
				d := float64(v) - mean[j]
				mean[j] += d / n
				m2[j] += d * (float64(v) - mean[j])
			}
		}
	})
	if err != nil {
		return err
	}
	if trainCount == 0 || len(valid) == 0 {
		return fmt.Errorf("need training and validation records: %d before week %d, %d from it (adjust -valid-from-week)", trainCount, *validFrom, len(valid))
	}
	log.Printf("training on %d records (%.1f%% malicious), validating on %d (weeks >= %d)",
		trainCount, 100*float64(trainMalicious)/float64(trainCount), len(valid), *validFrom)

	m := newMLP(hidden, *seed)
	for j := range m.Mean {
		m.Mean[j] = float32(mean[j])
		std := math.Sqrt(m2[j] / n)
		if std < 1e-6 {
			std = 1 // a constant feature: leave it unscaled
		}
		m.Std[j] = float32(std)
	}
	validLabels := labelsOf(valid)

	t := newTrainer(m, *workers, *lr, *decay)
	rng := rand.New(rand.NewPCG(*seed, *seed+1))
	best, bestAUC, bad := m.clone(), -1.0, 0
	const block = 1024 // records per read; an epoch visits blocks in random order
	const groupBlocks = 32
	blocks := int((train.Count + block - 1) / block)
	buf := make([]byte, block*recordSize)
	group := make([]sample, 0, groupBlocks*block)
	read := make([]sample, block)

	for epoch := 1; epoch <= *epochs; epoch++ {
		started := time.Now()
		order := rng.Perm(blocks)
		var lossSum float64
		var batches int
		for g := 0; g < len(order); g += groupBlocks {
			// Read a group of random blocks, shuffle its records together, train on it
			group = group[:0]
			for _, b := range order[g:min(g+groupBlocks, len(order))] {
				first := int64(b) * block
				count := int(min(int64(block), train.Count-first))
				if err := train.ReadRange(first, read[:count], buf); err != nil {
					return err
				}
				for i := range read[:count] {
					if !isValid(&read[i]) && inSample(first+int64(i)) {
						group = append(group, read[i])
					}
				}
			}
			rng.Shuffle(len(group), func(i, j int) { group[i], group[j] = group[j], group[i] })
			for lo := 0; lo < len(group); lo += *batchSize {
				lossSum += t.batch(group[lo:min(lo+*batchSize, len(group))])
				batches++
			}
		}

		validAUC := auc(m.score(valid, *workers), validLabels)
		log.Printf("epoch %d/%d: loss %.4f, validation AUC %.5f (%s)",
			epoch, *epochs, lossSum/float64(max(batches, 1)), validAUC, time.Since(started).Round(time.Second))
		if validAUC > bestAUC {
			best, bestAUC, bad = m.clone(), validAUC, 0
		} else if bad++; bad >= *patience {
			log.Printf("no better validation AUC in %d epochs; stopping", *patience)
			break
		}
	}
	m = best

	// The threshold: the score at which -target-fpr of the validation set's benign files are flagged
	validScores := m.score(valid, *workers)
	threshold := thresholdForFPR(validScores, validLabels, *targetFPR)
	metadata := map[string]string{
		"panoptes.feature_version": strconv.Itoa(featureVersion),
		"panoptes.trained_on":      fmt.Sprintf("EMBER2024 %s: %d records before week %d", filepath.Base(*data), trainCount, *validFrom),
		"panoptes.hidden_layers":   *hiddenFlag,
		"panoptes.target_fpr":      fmt.Sprint(*targetFPR),
		"panoptes.threshold":       fmt.Sprint(threshold),
		"panoptes.threshold_baked": strconv.FormatBool(*calibrate),
	}
	report := func(name string, scores []float32, labels []float32) {
		r := evaluate(scores, labels, threshold)
		log.Printf("%-10s AUC %.5f  at threshold %.4f: detects %.2f%% of %d malicious, flags %.3f%% of %d benign",
			name, r.AUC, threshold, 100*r.TPR, r.Malicious, 100*r.FPR, r.Benign)
		metadata["panoptes."+name+"_auc"] = fmt.Sprintf("%.5f", r.AUC)
		metadata["panoptes."+name+"_tpr"] = fmt.Sprintf("%.5f", r.TPR)
		metadata["panoptes."+name+"_fpr"] = fmt.Sprintf("%.5f", r.FPR)
	}
	report("validation", validScores, validLabels)
	for _, split := range []string{splitTest, splitChallenge} {
		samples, err := loadAll(filepath.Join(*data, split+".pmlf"))
		if errors.Is(err, os.ErrNotExist) || (err == nil && len(samples) == 0) {
			log.Printf("%-10s no %s.pmlf records; skipped", split, split)
			continue
		}
		if err != nil {
			return err
		}
		report(split, m.score(samples, *workers), labelsOf(samples))
	}

	if onTrained != nil {
		onTrained(m, threshold)
	}
	model := exportONNX(m, threshold, *calibrate, metadata)
	if err := os.WriteFile(*out, model, 0o644); err != nil {
		return err
	}
	log.Printf("wrote %s (%d KB). Put it at assets/ml/model.onnx (or next to PanoptesML.dll) to use it", *out, len(model)/1024)
	if *calibrate {
		log.Printf("the threshold is baked in: the model scores %.4f as 0.5, so PanoptesML's fixed 0.5 threshold applies it", threshold)
	}
	return nil
}

// ensureConverted converts the EMBER folders into dir unless it already holds a finished
// conversion of the same files
func ensureConverted(src *sourceFlags, dir string, force bool, workers int) error {
	sources, err := src.sources()
	if err != nil {
		return err
	}
	keep := src.keep()
	if !force {
		done, err := convertedFor(dir, sources, keep)
		if err != nil {
			return err
		}
		if done {
			log.Printf("using the features already converted in %s (-reconvert to redo them)", dir)
			return nil
		}
	}
	log.Printf("converting %d EMBER files into %s; later runs reuse it", len(sources), dir)
	return convertSources(sources, keep, dir, workers)
}

// onTrained, when set (by tests), receives the final network and threshold before export
var onTrained func(m *mlp, threshold float32)

func parseSizes(s string) ([]int, error) {
	var sizes []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad layer size %q in %q", part, s)
		}
		sizes = append(sizes, n)
	}
	return sizes, nil
}

func labelsOf(samples []sample) []float32 {
	labels := make([]float32, len(samples))
	for i := range samples {
		labels[i] = samples[i].Label
	}
	return labels
}

// loadAll reads a whole dataset into memory: the test sets, a few hundred thousand records
func loadAll(path string) ([]sample, error) {
	d, err := openDataset(path)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	samples := make([]sample, 0, d.Count)
	err = d.ForEach(func(block []sample) { samples = append(samples, block...) })
	return samples, err
}
