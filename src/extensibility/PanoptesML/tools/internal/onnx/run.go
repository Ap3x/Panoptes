package onnx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Runner evaluates a decoded model on one feature vector at a time, in Go. It supports the few
// operators PanoptesML's models use (MatMul, Add, Relu, Sigmoid), on float tensors with a batch
// of one; it is for evaluating models on datasets without ONNX Runtime, not a general runtime.
// Any other operator is an error at Decode
type Runner struct {
	Metadata map[string]string
	input    string
	output   string
	nodes    []node
	inits    map[string]tensor
}

type node struct {
	op     string
	inputs []string
	output string
}

// tensor is a float tensor: a vector ([n]) or a matrix ([rows, cols], row-major)
type tensor struct {
	dims []int64
	data []float32
}

var supported = map[string]bool{"MatMul": true, "Add": true, "Relu": true, "Sigmoid": true}

// field is one protobuf field: its number, wire type and value (varint or bytes)
type field struct {
	num   int
	wire  int
	value uint64
	bytes []byte
}

func readVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("bad varint")
}

func fields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		key, n, err := readVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		f := field{num: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			if f.value, n, err = readVarint(b); err != nil {
				return nil, err
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("truncated fixed64")
			}
			f.value, b = binary.LittleEndian.Uint64(b), b[8:]
		case 2:
			size, n, err := readVarint(b)
			if err != nil || uint64(len(b)-n) < size {
				return nil, errors.New("truncated field")
			}
			f.bytes, b = b[n:n+int(size)], b[n+int(size):]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("truncated fixed32")
			}
			f.value, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out, nil
}

func nameOf(valueInfo []byte) (string, error) {
	fs, err := fields(valueInfo)
	for _, f := range fs {
		if f.num == 1 {
			return string(f.bytes), nil
		}
	}
	return "", err
}

func decodeTensor(b []byte) (string, tensor, error) {
	fs, err := fields(b)
	if err != nil {
		return "", tensor{}, err
	}
	var name string
	var t tensor
	for _, f := range fs {
		switch f.num {
		case 1: // dims: varints, or packed
			if f.wire == 0 {
				t.dims = append(t.dims, int64(f.value))
			} else {
				for p := f.bytes; len(p) > 0; {
					v, n, err := readVarint(p)
					if err != nil {
						return "", t, err
					}
					t.dims, p = append(t.dims, int64(v)), p[n:]
				}
			}
		case 2:
			if f.value != tensorFloat {
				return "", t, fmt.Errorf("tensor data type %d; only float is supported", f.value)
			}
		case 4: // float_data: packed, or one fixed32 each
			if f.wire == 5 {
				t.data = append(t.data, math.Float32frombits(uint32(f.value)))
			} else {
				for i := 0; i+4 <= len(f.bytes); i += 4 {
					t.data = append(t.data, math.Float32frombits(binary.LittleEndian.Uint32(f.bytes[i:])))
				}
			}
		case 8:
			name = string(f.bytes)
		case 9: // raw_data
			for i := 0; i+4 <= len(f.bytes); i += 4 {
				t.data = append(t.data, math.Float32frombits(binary.LittleEndian.Uint32(f.bytes[i:])))
			}
		}
	}
	return name, t, nil
}

// Decode reads a model and checks that the Runner can evaluate it
func Decode(model []byte) (*Runner, error) {
	top, err := fields(model)
	if err != nil {
		return nil, fmt.Errorf("not an ONNX model: %w", err)
	}
	r := &Runner{Metadata: map[string]string{}, inits: map[string]tensor{}}
	var graph []byte
	for _, f := range top {
		switch f.num {
		case 7:
			graph = f.bytes
		case 14:
			kv, err := fields(f.bytes)
			if err != nil {
				return nil, err
			}
			var k, v string
			for _, e := range kv {
				if e.num == 1 {
					k = string(e.bytes)
				} else if e.num == 2 {
					v = string(e.bytes)
				}
			}
			r.Metadata[k] = v
		}
	}
	gf, err := fields(graph)
	if err != nil || graph == nil {
		return nil, errors.New("the model has no graph")
	}
	var inputs, outputs []string
	for _, f := range gf {
		switch f.num {
		case 1:
			nf, err := fields(f.bytes)
			if err != nil {
				return nil, err
			}
			var n node
			for _, e := range nf {
				switch e.num {
				case 1:
					n.inputs = append(n.inputs, string(e.bytes))
				case 2:
					n.output = string(e.bytes)
				case 4:
					n.op = string(e.bytes)
				}
			}
			if !supported[n.op] {
				return nil, fmt.Errorf("operator %s isn't supported (only MatMul, Add, Relu, Sigmoid)", n.op)
			}
			r.nodes = append(r.nodes, n)
		case 5:
			name, t, err := decodeTensor(f.bytes)
			if err != nil {
				return nil, err
			}
			r.inits[name] = t
		case 11:
			name, err := nameOf(f.bytes)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, name)
		case 12:
			name, err := nameOf(f.bytes)
			if err != nil {
				return nil, err
			}
			outputs = append(outputs, name)
		}
	}
	// Initializers may also be listed as inputs (older exporters); the feature input is the other
	for _, in := range inputs {
		if _, ok := r.inits[in]; !ok {
			r.input = in
		}
	}
	if r.input == "" || len(outputs) == 0 {
		return nil, errors.New("the graph needs an input and an output")
	}
	r.output = outputs[0]
	return r, nil
}

// Run returns the last value of the model's first output for one feature vector, as
// PanoptesML reads the score
func (r *Runner) Run(features []float32) (float32, error) {
	values := map[string]tensor{r.input: {dims: []int64{1, int64(len(features))}, data: features}}
	get := func(name string) (tensor, error) {
		if t, ok := values[name]; ok {
			return t, nil
		}
		if t, ok := r.inits[name]; ok {
			return t, nil
		}
		return tensor{}, fmt.Errorf("no value %q", name)
	}
	for _, n := range r.nodes {
		a, err := get(n.inputs[0])
		if err != nil {
			return 0, err
		}
		out := tensor{dims: a.dims}
		switch n.op {
		case "MatMul":
			w, err := get(n.inputs[1])
			if err != nil {
				return 0, err
			}
			if len(w.dims) != 2 || int64(len(a.data)) != w.dims[0] {
				return 0, fmt.Errorf("MatMul %s: %d values by %v", n.output, len(a.data), w.dims)
			}
			rows, cols := int(w.dims[0]), int(w.dims[1])
			out = tensor{dims: []int64{1, int64(cols)}, data: make([]float32, cols)}
			for i := 0; i < rows; i++ {
				x := a.data[i]
				if x == 0 {
					continue
				}
				row := w.data[i*cols : (i+1)*cols]
				for j := range row {
					out.data[j] += x * row[j]
				}
			}
		case "Add":
			b, err := get(n.inputs[1])
			if err != nil {
				return 0, err
			}
			if len(b.data) != len(a.data) && len(b.data) != 1 {
				return 0, fmt.Errorf("Add %s: %d and %d values", n.output, len(a.data), len(b.data))
			}
			out.data = make([]float32, len(a.data))
			for i := range a.data {
				out.data[i] = a.data[i] + b.data[i%len(b.data)]
			}
		case "Relu":
			out.data = make([]float32, len(a.data))
			for i, v := range a.data {
				out.data[i] = max(v, 0)
			}
		case "Sigmoid":
			out.data = make([]float32, len(a.data))
			for i, v := range a.data {
				out.data[i] = float32(1 / (1 + math.Exp(-float64(v))))
			}
		}
		values[n.output] = out
	}
	t, err := get(r.output)
	if err != nil || len(t.data) == 0 {
		return 0, fmt.Errorf("output %q: %v", r.output, err)
	}
	return t.data[len(t.data)-1], nil
}
