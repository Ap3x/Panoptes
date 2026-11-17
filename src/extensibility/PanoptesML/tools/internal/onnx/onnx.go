// Package onnx writes ONNX models without an ONNX or protobuf library. An ONNX model is a
// protobuf message (onnx.ModelProto), so the few messages PanoptesML's models need are encoded
// here directly, with the field numbers from onnx-ml.proto. To check a model's structure, decode
// it with protoc:
//
//	protoc -I <vcpkg_installed>/x64-windows-static/include --decode=onnx.ModelProto onnx/onnx-ml.proto < model.onnx
package onnx

import (
	"encoding/binary"
	"math"
	"sort"
)

// Protobuf wire format: each field is a tag (field number and wire type) and a value
const (
	wireVarint = 0
	wireBytes  = 2 // length-delimited: strings, bytes and embedded messages
)

func varint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func tag(field, wire int) []byte { return varint(uint64(field<<3 | wire)) }

func intField(field int, v int64) []byte { return append(tag(field, wireVarint), varint(uint64(v))...) }

func bytesField(field int, data []byte) []byte {
	b := append(tag(field, wireBytes), varint(uint64(len(data)))...)
	return append(b, data...)
}

func stringField(field int, s string) []byte { return bytesField(field, []byte(s)) }

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

const tensorFloat = 1 // TensorProto.DataType.FLOAT

// Dim is one dimension of a value's shape: a fixed size (int) or a symbolic name (string), such
// as "N" for the batch size
type Dim any

// ValueInfo is a ValueInfoProto for a float tensor: a graph input or output
func ValueInfo(name string, dims ...Dim) []byte {
	var shape []byte // TensorShapeProto
	for _, d := range dims {
		switch v := d.(type) {
		case int:
			shape = append(shape, bytesField(1, intField(1, int64(v)))...) // dim { dim_value }
		case string:
			shape = append(shape, bytesField(1, stringField(2, v))...) // dim { dim_param }
		}
	}
	tensorType := concat(intField(1, tensorFloat), bytesField(2, shape)) // TypeProto.Tensor
	return concat(
		stringField(1, name),                     // name
		bytesField(2, bytesField(1, tensorType)), // type { tensor_type }
	)
}

// Tensor is a float TensorProto (an initializer: weights or biases), holding the values as
// little-endian raw_data
func Tensor(name string, dims []int64, values []float32) []byte {
	var b []byte
	for _, d := range dims {
		b = append(b, intField(1, d)...) // dims
	}
	raw := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(raw[4*i:], math.Float32bits(v))
	}
	return concat(b,
		intField(2, tensorFloat), // data_type
		stringField(8, name),     // name
		bytesField(9, raw),       // raw_data
	)
}

// Node is a NodeProto: an operator of the default ONNX domain with its inputs and one output
func Node(op string, inputs []string, output string) []byte {
	var b []byte
	for _, in := range inputs {
		b = append(b, stringField(1, in)...) // input
	}
	return concat(b,
		stringField(2, output), // output
		stringField(4, op),     // op_type
	)
}

// Graph is a GraphProto
type Graph struct {
	Name         string
	Nodes        [][]byte // from Node, in execution order
	Initializers [][]byte // from Tensor
	Inputs       [][]byte // from ValueInfo
	Outputs      [][]byte // from ValueInfo
}

func (g Graph) encode() []byte {
	var b []byte
	for _, n := range g.Nodes {
		b = append(b, bytesField(1, n)...)
	}
	b = append(b, stringField(2, g.Name)...)
	for _, t := range g.Initializers {
		b = append(b, bytesField(5, t)...)
	}
	for _, in := range g.Inputs {
		b = append(b, bytesField(11, in)...)
	}
	for _, out := range g.Outputs {
		b = append(b, bytesField(12, out)...)
	}
	return b
}

// Model is a ModelProto
type Model struct {
	Producer string
	Doc      string
	Graph    Graph
	// Metadata is written as metadata_props: free-form key/value pairs that travel with the
	// model (training data, threshold, metrics)
	Metadata map[string]string
}

// Encode returns the model's bytes, ready to save as a .onnx file. It uses IR version 8 and
// opset 13 of the default domain, which ONNX Runtime 1.10 and later read
func (m Model) Encode() []byte {
	b := concat(
		intField(1, 8),                  // ir_version
		stringField(2, m.Producer),      // producer_name
		stringField(6, m.Doc),           // doc_string
		bytesField(7, m.Graph.encode()), // graph
		bytesField(8, concat(stringField(1, ""), intField(2, 13))), // opset_import: default domain, 13
	)
	keys := make([]string, 0, len(m.Metadata))
	for k := range m.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys) // the same model always encodes to the same bytes
	for _, k := range keys {
		entry := concat(stringField(1, k), stringField(2, m.Metadata[k])) // StringStringEntryProto
		b = append(b, bytesField(14, entry)...)                           // metadata_props
	}
	return b
}
