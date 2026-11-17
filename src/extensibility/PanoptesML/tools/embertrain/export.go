package main

import (
	"fmt"
	"math"

	"github.com/Ap3x/Panoptes/mltools/internal/onnx"
)

// exportONNX writes the network as the model PanoptesML loads: float features [N, 278] in,
// float score [N, 1] out, built from MatMul, Add, Relu and Sigmoid.
//
// The standardization is folded into the first layer, so the model takes the raw features:
// W(x - mean)/std + b = (W/std)x + (b - W(mean/std)).
//
// With bakeThreshold, the output logit is shifted by logit(threshold), so a file scores 0.5
// exactly where it scores threshold unshifted: PanoptesML's fixed 0.5 threshold then flags at
// the chosen false-positive rate. Scores are no longer probabilities then, only a ranking.
func exportONNX(m *mlp, threshold float32, bakeThreshold bool, metadata map[string]string) []byte {
	var nodes, initializers [][]byte
	input := "features"
	for l := 0; l < m.layers(); l++ {
		nIn, nOut := m.Sizes[l], m.Sizes[l+1]
		w := m.Params[m.wOff[l] : m.wOff[l]+nIn*nOut]
		b := append([]float32(nil), m.Params[m.bOff[l]:m.bOff[l]+nOut]...)

		// ONNX MatMul takes [in, out]; the network stores [out][in]
		weights := make([]float32, nIn*nOut)
		for j := 0; j < nOut; j++ {
			for i := 0; i < nIn; i++ {
				v := w[j*nIn+i]
				if l == 0 {
					b[j] -= v * m.Mean[i] / m.Std[i]
					v /= m.Std[i]
				}
				weights[i*nOut+j] = v
			}
		}
		if l == m.layers()-1 && bakeThreshold {
			t := math.Min(math.Max(float64(threshold), 1e-7), 1-1e-7)
			b[0] -= float32(math.Log(t / (1 - t)))
		}

		wName, bName := fmt.Sprintf("w%d", l), fmt.Sprintf("b%d", l)
		initializers = append(initializers,
			onnx.Tensor(wName, []int64{int64(nIn), int64(nOut)}, weights),
			onnx.Tensor(bName, []int64{int64(nOut)}, b))
		matmul, sum := fmt.Sprintf("matmul%d", l), fmt.Sprintf("dense%d", l)
		nodes = append(nodes,
			onnx.Node("MatMul", []string{input, wName}, matmul),
			onnx.Node("Add", []string{matmul, bName}, sum))
		if l < m.layers()-1 {
			act := fmt.Sprintf("relu%d", l)
			nodes = append(nodes, onnx.Node("Relu", []string{sum}, act))
			input = act
		} else {
			nodes = append(nodes, onnx.Node("Sigmoid", []string{sum}, "score"))
		}
	}

	return onnx.Model{
		Producer: "panoptes-embertrain",
		Doc:      "PanoptesML malware classifier (feature version 1) trained on EMBER2024 with embertrain",
		Graph: onnx.Graph{
			Name:         "panoptes_ml_mlp",
			Nodes:        nodes,
			Initializers: initializers,
			Inputs:       [][]byte{onnx.ValueInfo("features", "N", featureCount)},
			Outputs:      [][]byte{onnx.ValueInfo("score", "N", 1)},
		},
		Metadata: metadata,
	}.Encode()
}
