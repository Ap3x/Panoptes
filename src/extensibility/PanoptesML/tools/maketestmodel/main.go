// maketestmodel writes a placeholder model.onnx for testing PanoptesML end to end.
//
// It is NOT a detector: it is a fixed logistic regression that leans on a few features (high
// section entropy, writable+executable sections, an entry point outside executable code, a large
// overlay), so the pipeline can be exercised before a real model has been trained (see
// embertrain for training one).
//
//	cd src/extensibility/PanoptesML/tools
//	go run ./maketestmodel ../../../../assets/ml/model.onnx
//
// The input is float [N, 278] in the order of PanoMlFeature (include/PanoptesML.h); the output
// is float [N, 1], the malicious probability.
package main

import (
	"fmt"
	"os"

	"github.com/Ap3x/Panoptes/mltools/internal/onnx"
)

const featureCount = 278 // FEATURE_COUNT

// Indices from PanoMlFeature
const (
	sectionEntropyMax          = 263
	writableExecutableSections = 266
	entryOutsideExecutable     = 267
	overlayRatio               = 275
)

// placeholderModel builds sigmoid(features x weights + bias)
func placeholderModel() []byte {
	weights := make([]float32, featureCount)
	weights[sectionEntropyMax] = 6.0
	weights[writableExecutableSections] = 3.0
	weights[entryOutsideExecutable] = 2.0
	weights[overlayRatio] = 2.0
	const bias = -7.0

	return onnx.Model{
		Producer: "panoptes-maketestmodel",
		Doc:      "Placeholder for testing PanoptesML; not a detector",
		Graph: onnx.Graph{
			Name: "panoptes_ml_placeholder",
			Nodes: [][]byte{
				onnx.Node("MatMul", []string{"features", "weights"}, "logit_raw"),
				onnx.Node("Add", []string{"logit_raw", "bias"}, "logit"),
				onnx.Node("Sigmoid", []string{"logit"}, "score"),
			},
			Initializers: [][]byte{
				onnx.Tensor("weights", []int64{featureCount, 1}, weights),
				onnx.Tensor("bias", []int64{1}, []float32{bias}),
			},
			Inputs:  [][]byte{onnx.ValueInfo("features", "N", featureCount)},
			Outputs: [][]byte{onnx.ValueInfo("score", "N", 1)},
		},
		Metadata: map[string]string{"panoptes.feature_version": "1"},
	}.Encode()
}

func main() {
	out := "model.onnx"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	model := placeholderModel()
	if err := os.WriteFile(out, model, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", out, len(model))
}
