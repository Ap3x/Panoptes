package main

import (
	"math"
	"sort"
)

// auc is the area under the ROC curve: the chance a random malicious sample scores above a
// random benign one. Ties count half
func auc(scores []float32, labels []float32) float64 {
	idx := make([]int, len(scores))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return scores[idx[a]] < scores[idx[b]] })

	// Rank-sum (Mann-Whitney U), with tied scores sharing their average rank
	var rankSum float64
	positives := 0
	for i := 0; i < len(idx); {
		j := i
		for j < len(idx) && scores[idx[j]] == scores[idx[i]] {
			j++
		}
		rank := float64(i+j+1) / 2 // average of ranks i+1..j
		for k := i; k < j; k++ {
			if labels[idx[k]] == 1 {
				rankSum += rank
				positives++
			}
		}
		i = j
	}
	negatives := len(scores) - positives
	if positives == 0 || negatives == 0 {
		return math.NaN()
	}
	return (rankSum - float64(positives)*float64(positives+1)/2) / (float64(positives) * float64(negatives))
}

// thresholdForFPR returns the lowest threshold at which at most targetFPR of the benign samples
// score at or above it (PanoptesML flags score >= threshold)
func thresholdForFPR(scores []float32, labels []float32, targetFPR float64) float32 {
	var benign []float32
	for i, s := range scores {
		if labels[i] == 0 {
			benign = append(benign, s)
		}
	}
	if len(benign) == 0 {
		return 0.5
	}
	sort.Slice(benign, func(a, b int) bool { return benign[a] > benign[b] })
	allowed := int(targetFPR * float64(len(benign))) // benign samples allowed at or above it
	if allowed >= len(benign) {
		return 0
	}
	// Just above the first benign score that must stay below the threshold
	return math.Nextafter32(benign[allowed], 1)
}

type rates struct {
	TPR, FPR          float64 // at the threshold
	Malicious, Benign int
	AUC               float64
}

func evaluate(scores []float32, labels []float32, threshold float32) rates {
	var r rates
	var tp, fp int
	for i, s := range scores {
		if labels[i] == 1 {
			r.Malicious++
			if s >= threshold {
				tp++
			}
		} else {
			r.Benign++
			if s >= threshold {
				fp++
			}
		}
	}
	if r.Malicious > 0 {
		r.TPR = float64(tp) / float64(r.Malicious)
	}
	if r.Benign > 0 {
		r.FPR = float64(fp) / float64(r.Benign)
	}
	r.AUC = auc(scores, labels)
	return r
}
