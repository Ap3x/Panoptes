package main

import (
	"math"
	"strings"
)

// Feature version 1, as PanoptesML computes it (src/pe_features.cpp). Every index and formula
// here must match the C++: a model trained on features computed differently from the ones the
// DLL computes at scan time is wrong in ways no metric here shows. Check with `embertrain
// inspect` against `PanoptesMLQuery -json` on the same files.
const (
	featureVersion = 1
	featureCount   = 278

	fByteHistogram              = 0 // 256 values
	fEntropy                    = 256
	fLogSize                    = 257
	fIsPe                       = 258
	fIs64Bit                    = 259
	fIsDll                      = 260
	fSubsystemGui               = 261
	fSectionCount               = 262
	fSectionEntropyMax          = 263
	fSectionEntropyMin          = 264
	fSectionEntropyMean         = 265
	fWritableExecutableSections = 266
	fEntryOutsideExecutable     = 267
	fImportedDlls               = 268
	fImportedFunctions          = 269
	fHasSignature               = 270
	fHasTls                     = 271
	fHasDebug                   = 272
	fHasRelocations             = 273
	fHasResources               = 274
	fOverlayRatio               = 275
	fImageToFileRatio           = 276
	fZeroTimestamp              = 277
)

const (
	magicPE32     = 0x10b // IMAGE_NT_OPTIONAL_HDR32_MAGIC
	magicPE32Plus = 0x20b // IMAGE_NT_OPTIONAL_HDR64_MAGIC
)

// emberRecord holds the parts of an EMBER2024 record (one JSONL line, thrember feature version
// 3 raw features plus labels) the features need. Every other field is skipped while decoding
type emberRecord struct {
	Sha256    string    `json:"sha256"`
	Label     *int      `json:"label"` // 0 benign, 1 malicious
	FileType  string    `json:"file_type"`
	WeekID    int       `json:"week_id"`
	Histogram []float64 `json:"histogram"` // raw byte counts
	General   struct {
		Size    float64 `json:"size"`
		Entropy float64 `json:"entropy"` // bits per byte, 0..8
		IsPe    int     `json:"is_pe"`
	} `json:"general"`
	Header struct {
		Coff struct {
			Timestamp       int64    `json:"timestamp"`
			Characteristics []string `json:"characteristics"` // IMAGE_FILE_ names without the prefix
		} `json:"coff"`
		Optional struct {
			Magic               int     `json:"magic"`
			Subsystem           string  `json:"subsystem"`
			SizeofImage         float64 `json:"sizeof_image"`
			AddressOfEntrypoint int64   `json:"address_of_entrypoint"`
		} `json:"optional"`
	} `json:"header"`
	Section struct {
		Entry    string `json:"entry"` // lowercased name of the section holding the entry point
		Sections []struct {
			Name    string   `json:"name"`
			Size    float64  `json:"size"` // SizeOfRawData
			Entropy float64  `json:"entropy"`
			Props   []string `json:"props"` // IMAGE_SCN_ names without the prefix
		} `json:"sections"`
		Overlay struct {
			SizeRatio float64 `json:"size_ratio"`
		} `json:"overlay"`
	} `json:"section"`
	Imports         map[string][]string `json:"imports"`
	DataDirectories []struct {
		Name           string  `json:"name"` // IMAGE_DIRECTORY_ENTRY_ names without the prefix
		Size           float64 `json:"size"`
		VirtualAddress float64 `json:"virtual_address"`
	} `json:"datadirectories"`
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// toFeatures computes PanoptesML's feature version 1 from an EMBER record. It returns false
// when the record is a PE the C++ would also reject (no PE32/PE32+ optional header), with the
// byte statistics still filled in, as the C++ does
func toFeatures(r *emberRecord, f *[featureCount]float32) (isPe bool) {
	*f = [featureCount]float32{}
	size := r.General.Size

	// Byte statistics, for every file: counts / size, entropy / 8, log2(size + 1) / 32
	if size > 0 {
		for b := 0; b < 256 && b < len(r.Histogram); b++ {
			f[fByteHistogram+b] = float32(r.Histogram[b] / size)
		}
	}
	f[fEntropy] = float32(r.General.Entropy) / 8
	f[fLogSize] = float32(math.Log2(size+1) / 32)

	// ParsePe accepts only a PE32 or PE32+ optional header
	magic := r.Header.Optional.Magic
	if r.General.IsPe != 1 || (magic != magicPE32 && magic != magicPE32Plus) {
		return false
	}
	f[fIsPe] = 1
	f[fIs64Bit] = boolf(magic == magicPE32Plus)
	f[fIsDll] = boolf(contains(r.Header.Coff.Characteristics, "DLL"))
	f[fSubsystemGui] = boolf(r.Header.Optional.Subsystem == "IMAGE_SUBSYSTEM_WINDOWS_GUI")
	f[fZeroTimestamp] = boolf(r.Header.Coff.Timestamp == 0)
	sections := r.Section.Sections
	f[fSectionCount] = float32(math.Min(float64(len(sections))/16, 4))

	// Sections: entropy over those with raw data, W+X sections / section count
	entropyMax, entropyMin, entropySum := 0.0, 8.0, 0.0
	withData, writableExecutable := 0, 0
	entryInExecutable := false
	for _, s := range sections {
		executable := contains(s.Props, "MEM_EXECUTE")
		if executable && contains(s.Props, "MEM_WRITE") {
			writableExecutable++
		}
		// thrember names the entry point's section (lowercased); without a VirtualAddress per
		// section this is the closest to the C++'s address check. Where the entry point is in
		// no section, thrember names the first executable one instead, so a feature value of 1
		// from that case can't be reproduced here: the C++ sees it, the training data doesn't
		if executable && strings.EqualFold(strings.TrimRight(s.Name, "\x00"), r.Section.Entry) {
			entryInExecutable = true
		}
		if s.Size == 0 {
			continue
		}
		entropyMax = math.Max(entropyMax, s.Entropy)
		entropyMin = math.Min(entropyMin, s.Entropy)
		entropySum += s.Entropy
		withData++
	}
	if withData > 0 {
		f[fSectionEntropyMax] = float32(entropyMax) / 8
		f[fSectionEntropyMin] = float32(entropyMin) / 8
		f[fSectionEntropyMean] = float32(entropySum) / float32(withData) / 8
	}
	if len(sections) > 0 {
		f[fWritableExecutableSections] = float32(writableExecutable) / float32(len(sections))
	}
	// A DLL without an entry point has AddressOfEntryPoint 0, which is not suspicious
	f[fEntryOutsideExecutable] = boolf(r.Header.Optional.AddressOfEntrypoint != 0 && !entryInExecutable)
	f[fOverlayRatio] = float32(r.Section.Overlay.SizeRatio)
	if size > 0 {
		f[fImageToFileRatio] = float32(math.Min(r.Header.Optional.SizeofImage/size, 16) / 16)
	}

	// Imports: DLLs and functions (ordinal imports included), log-scaled
	functions := 0
	for _, list := range r.Imports {
		functions += len(list)
	}
	f[fImportedDlls] = float32(math.Log2(float64(len(r.Imports))+1) / 8)
	f[fImportedFunctions] = float32(math.Log2(float64(functions)+1) / 12)

	// Data directories count as present with a non-zero address and size (Directory() in C++)
	for _, d := range r.DataDirectories {
		present := d.Size > 0 && d.VirtualAddress > 0
		switch d.Name {
		case "SECURITY":
			f[fHasSignature] = boolf(present)
		case "TLS":
			f[fHasTls] = boolf(present)
		case "DEBUG":
			f[fHasDebug] = boolf(present)
		case "BASERELOC":
			f[fHasRelocations] = boolf(present)
		case "RESOURCE":
			f[fHasResources] = boolf(present)
		}
	}
	return true
}

func boolf(b bool) float32 {
	if b {
		return 1
	}
	return 0
}
