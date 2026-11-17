// embertrain trains PanoptesML's model on the EMBER2024 dataset. It is plain Go with no cgo, so
// it cross-compiles to one static binary for a NAS or any Linux box:
//
//	cd src/extensibility/PanoptesML/tools
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o embertrain ./embertrain   (arm64 for ARM NASes)
//
// Then, on the machine with the data:
//
//	embertrain train -data Win64_train/ Win32_train/ Dot_Net_train/ -out model.onnx
//	embertrain inspect /volume1/ember/Win64/part.jsonl     (features of a few records, for parity checks)
//
// train turns EMBER2024's JSONL records (thrember feature version 3) into PanoptesML's 278
// features (feature version 1, the layout in include/PanoptesML.h) the first time, in -cache, and
// reuses them on later runs. It then fits a small neural network on them and writes model.onnx,
// which PanoptesML loads. convert does only the first step.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
)

func defaultWorkers() int { return max(runtime.NumCPU(), 1) }

func usage() {
	fmt.Fprint(os.Stderr, `Usage: embertrain <command> [flags]

Commands:
  train     EMBER2024 JSONL folders -> model.onnx, with validation, test and challenge results
            (converts the folders to PanoptesML features the first time and reuses them after)
  convert   only the conversion: JSONL folders -> train.pmlf, test.pmlf, challenge.pmlf
  eval      score EMBER2024 records with a model.onnx: AUC, detection and false positives by week
  inspect   print the PanoptesML features of EMBER records, one JSON line each

Run "embertrain <command> -h" for a command's flags.
`)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "convert":
		err = runConvert(os.Args[2:])
	case "train":
		err = runTrain(os.Args[2:])
	case "eval":
		err = runEval(os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "-h", "-help", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

// runInspect prints each record's features in the shape PanoptesMLQuery -json uses, so the two
// can be compared feature by feature for the same file (match them by sha256)
func runInspect(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: embertrain inspect <file.jsonl>... (or - for stdin)")
	}
	encoder := json.NewEncoder(os.Stdout)
	for _, path := range args {
		var r io.Reader = os.Stdin
		if path != "-" {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		br := bufio.NewReaderSize(r, 1<<20)
		for {
			data, err := br.ReadBytes('\n')
			if len(data) > 1 {
				var rec emberRecord
				if jerr := json.Unmarshal(data, &rec); jerr != nil {
					return fmt.Errorf("%s: %w", path, jerr)
				}
				var f [featureCount]float32
				isPe := toFeatures(&rec, &f)
				label := -1
				if rec.Label != nil {
					label = *rec.Label
				}
				if eerr := encoder.Encode(struct {
					Sha256         string    `json:"sha256"`
					Label          int       `json:"label"`
					FileType       string    `json:"file_type"`
					IsPe           bool      `json:"is_pe"`
					FeatureVersion int       `json:"feature_version"`
					Features       []float32 `json:"features"`
				}{rec.Sha256, label, rec.FileType, isPe, featureVersion, f[:]}); eerr != nil {
					return eerr
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}
