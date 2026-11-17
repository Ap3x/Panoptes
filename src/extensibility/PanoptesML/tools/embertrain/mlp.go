package main

import (
	"math"
	"math/rand/v2"
	"sync"
)

// mlp is a fully connected network: featureCount inputs, ReLU hidden layers, and one output
// logit (the malicious probability is its sigmoid). The inputs are standardized with the
// training set's mean and standard deviation; export folds that into the first layer, so the
// ONNX model takes PanoptesML's raw features.
//
// Weights are stored [out][in], row by row, so each output is one dot product.
type mlp struct {
	Sizes []int // featureCount, hidden..., 1
	// Params holds every layer's weights then biases, flattened: layer l's weights at
	// wOff[l] (Sizes[l+1] x Sizes[l]) and its biases at bOff[l] (Sizes[l+1])
	Params     []float32
	wOff, bOff []int
	Mean, Std  [featureCount]float32
}

func newMLP(hidden []int, seed uint64) *mlp {
	m := &mlp{Sizes: append(append([]int{featureCount}, hidden...), 1)}
	n := 0
	for l := 0; l+1 < len(m.Sizes); l++ {
		m.wOff = append(m.wOff, n)
		n += m.Sizes[l] * m.Sizes[l+1]
		m.bOff = append(m.bOff, n)
		n += m.Sizes[l+1]
	}
	m.Params = make([]float32, n)

	// He initialization for the ReLU layers; biases start at 0
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	for l := 0; l+1 < len(m.Sizes); l++ {
		scale := math.Sqrt(2 / float64(m.Sizes[l]))
		w := m.Params[m.wOff[l] : m.wOff[l]+m.Sizes[l]*m.Sizes[l+1]]
		for i := range w {
			w[i] = float32(rng.NormFloat64() * scale)
		}
	}
	for i := range m.Std {
		m.Std[i] = 1
	}
	return m
}

func (m *mlp) layers() int { return len(m.Sizes) - 1 }

// scratch holds one worker's activations
type scratch struct {
	acts [][]float32 // acts[0] is the standardized input; acts[l+1] layer l's output (after ReLU)
	pre  [][]float32 // pre[l]: layer l's output before ReLU
	grad [][]float32 // grad[l]: the loss gradient at layer l's pre-activation
}

func (m *mlp) newScratch() *scratch {
	s := &scratch{}
	for l, n := range m.Sizes {
		s.acts = append(s.acts, make([]float32, n))
		if l > 0 {
			s.pre = append(s.pre, make([]float32, n))
			s.grad = append(s.grad, make([]float32, n))
		}
	}
	return s
}

func dot(a, b []float32) float32 {
	var sum float32
	b = b[:len(a)]
	for i, v := range a {
		sum += v * b[i]
	}
	return sum
}

// forward returns the output logit for one sample, keeping the activations in s
func (m *mlp) forward(x *[featureCount]float32, s *scratch) float32 {
	in := s.acts[0]
	for i := range in {
		in[i] = (x[i] - m.Mean[i]) / m.Std[i]
	}
	for l := 0; l < m.layers(); l++ {
		nIn, nOut := m.Sizes[l], m.Sizes[l+1]
		w := m.Params[m.wOff[l]:]
		b := m.Params[m.bOff[l]:]
		prev := s.acts[l]
		for j := 0; j < nOut; j++ {
			z := b[j] + dot(prev, w[j*nIn:(j+1)*nIn])
			s.pre[l][j] = z
			if l+1 < m.layers() && z < 0 {
				z = 0 // ReLU on the hidden layers; the output stays a logit
			}
			s.acts[l+1][j] = z
		}
	}
	return s.acts[m.layers()][0]
}

func sigmoid(z float32) float32 { return float32(1 / (1 + math.Exp(-float64(z)))) }

// backward adds one sample's gradient of the binary cross-entropy to g, after forward
func (m *mlp) backward(y float32, s *scratch, g []float32) {
	last := m.layers() - 1
	s.grad[last][0] = sigmoid(s.pre[last][0]) - y
	for l := last; l >= 0; l-- {
		nIn, nOut := m.Sizes[l], m.Sizes[l+1]
		w := m.Params[m.wOff[l]:]
		gw := g[m.wOff[l]:]
		gb := g[m.bOff[l]:]
		prev := s.acts[l]
		for j := 0; j < nOut; j++ {
			d := s.grad[l][j]
			if d == 0 {
				continue
			}
			gb[j] += d
			row := gw[j*nIn : (j+1)*nIn]
			for i, a := range prev {
				row[i] += d * a
			}
		}
		if l == 0 {
			break
		}
		// The gradient at the previous layer's pre-activation, through its ReLU
		down := s.grad[l-1]
		for i := range down {
			down[i] = 0
		}
		for j := 0; j < nOut; j++ {
			d := s.grad[l][j]
			if d == 0 {
				continue
			}
			row := w[j*nIn : (j+1)*nIn]
			for i := range down {
				down[i] += d * row[i]
			}
		}
		for i := range down {
			if s.pre[l-1][i] <= 0 {
				down[i] = 0
			}
		}
	}
}

// trainer runs mini-batch AdamW, splitting each batch across workers
type trainer struct {
	m            *mlp
	workers      int
	lr, decay    float64
	beta1, beta2 float64
	step         int
	mom, vel     []float32
	grads        [][]float32 // one per worker
	scratches    []*scratch
	loss         []float64 // per worker, summed over a batch
}

func newTrainer(m *mlp, workers int, lr, decay float64) *trainer {
	t := &trainer{m: m, workers: workers, lr: lr, decay: decay, beta1: 0.9, beta2: 0.999,
		mom: make([]float32, len(m.Params)), vel: make([]float32, len(m.Params)), loss: make([]float64, workers)}
	for range workers {
		t.grads = append(t.grads, make([]float32, len(m.Params)))
		t.scratches = append(t.scratches, m.newScratch())
	}
	return t
}

// batch trains on one batch and returns its mean loss
func (t *trainer) batch(samples []sample) float64 {
	var wg sync.WaitGroup
	per := (len(samples) + t.workers - 1) / t.workers
	for w := 0; w < t.workers; w++ {
		lo, hi := w*per, min((w+1)*per, len(samples))
		if lo >= hi {
			t.loss[w] = 0
			continue
		}
		wg.Add(1)
		go func(w, lo, hi int) {
			defer wg.Done()
			g, s := t.grads[w], t.scratches[w]
			clear(g)
			loss := 0.0
			for i := lo; i < hi; i++ {
				z := t.m.forward(&samples[i].Features, s)
				loss += bceWithLogits(z, samples[i].Label)
				t.m.backward(samples[i].Label, s, g)
			}
			t.loss[w] = loss
		}(w, lo, hi)
	}
	wg.Wait()

	// Sum the workers' gradients into the first, average, and take an AdamW step
	total := t.grads[0]
	for w := 1; w < t.workers; w++ {
		if w*per >= len(samples) {
			break
		}
		for i, v := range t.grads[w] {
			total[i] += v
		}
	}
	t.step++
	n := float32(len(samples))
	b1, b2 := float32(t.beta1), float32(t.beta2)
	c1 := 1 - math.Pow(t.beta1, float64(t.step))
	c2 := 1 - math.Pow(t.beta2, float64(t.step))
	lr := float32(t.lr * math.Sqrt(c2) / c1)
	decay := float32(t.lr * t.decay)
	p := t.m.Params
	for i := range p {
		g := total[i] / n
		t.mom[i] = b1*t.mom[i] + (1-b1)*g
		t.vel[i] = b2*t.vel[i] + (1-b2)*g*g
		p[i] -= lr*t.mom[i]/(float32(math.Sqrt(float64(t.vel[i])))+1e-8) + decay*p[i]
	}

	loss := 0.0
	for _, l := range t.loss {
		loss += l
	}
	return loss / float64(len(samples))
}

// bceWithLogits is the binary cross-entropy of sigmoid(z) against y, computed stably
func bceWithLogits(z, y float32) float64 {
	zf := float64(z)
	return math.Max(zf, 0) - zf*float64(y) + math.Log1p(math.Exp(-math.Abs(zf)))
}

// score returns sigmoid(logit) for every sample, in parallel
func (m *mlp) score(samples []sample, workers int) []float32 {
	scores := make([]float32, len(samples))
	var wg sync.WaitGroup
	per := (len(samples) + workers - 1) / workers
	for w := 0; w < workers; w++ {
		lo, hi := w*per, min((w+1)*per, len(samples))
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			s := m.newScratch()
			for i := lo; i < hi; i++ {
				scores[i] = sigmoid(m.forward(&samples[i].Features, s))
			}
		}(lo, hi)
	}
	wg.Wait()
	return scores
}

func (m *mlp) clone() *mlp {
	c := *m
	c.Params = append([]float32(nil), m.Params...)
	return &c
}
