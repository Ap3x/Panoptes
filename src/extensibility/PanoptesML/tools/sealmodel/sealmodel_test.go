package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

func TestSealRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	model := []byte("\x08\x08\x12\x0fthe model bytes")
	in, out, header := filepath.Join(dir, "model.onnx"), filepath.Join(dir, "model.sealed"), filepath.Join(dir, "key.h")
	os.WriteFile(in, model, 0o644)
	if err := run(in, out, header); err != nil {
		t.Fatal(err)
	}
	sealed, _ := os.ReadFile(out)
	if bytes.Contains(sealed, []byte("the model bytes")) {
		t.Fatal("the sealed model holds the plain model")
	}

	// The key, as the DLL rebuilds it from the header
	text, _ := os.ReadFile(header)
	arrays := regexp.MustCompile(`\{([^}]*)\}`).FindAllSubmatch(text, -1)
	if len(arrays) != 2 {
		t.Fatalf("want two key arrays in the header:\n%s", text)
	}
	parse := func(list []byte) []byte {
		var b []byte
		for _, m := range regexp.MustCompile(`0x[0-9a-f]{2}`).FindAll(list, -1) {
			v, _ := strconv.ParseUint(string(m[2:]), 16, 8)
			b = append(b, byte(v))
		}
		return b
	}
	masked, mask := parse(arrays[0][1]), parse(arrays[1][1])
	key := make([]byte, keySize)
	for i := range key {
		key[i] = masked[i] ^ mask[i]
	}

	plain, err := open(sealed, key)
	if err != nil || !bytes.Equal(plain, model) {
		t.Fatalf("open: %v, %q", err, plain)
	}
	if bytes.Equal(masked, key) || bytes.Equal(mask, key) {
		t.Error("the key is in the header as is")
	}
	for _, i := range []int{2, 9, len(sealed) - 1, len(sealed) / 2} { // header, nonce, tag, body
		bad := bytes.Clone(sealed)
		bad[i] ^= 1
		if _, err := open(bad, key); err == nil {
			t.Errorf("a change at byte %d went undetected", i)
		}
	}
}
