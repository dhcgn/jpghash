package jpghash

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"testing"
)

const benchJPEG = "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME.jpg"

// BenchmarkHashFile measures end-to-end throughput including os.Open and
// buffered I/O — i.e. what a CLI invocation actually pays.
func BenchmarkHashFile(b *testing.B) {
	info, err := os.Stat(benchJPEG)
	if err != nil {
		b.Fatalf("stat %s: %v", benchJPEG, err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()

	for b.Loop() {
		if _, err := HashFile(benchJPEG); err != nil {
			b.Fatalf("HashFile: %v", err)
		}
	}
}

// BenchmarkHashReader isolates the parser + hasher by serving bytes from
// memory, removing disk I/O from the measurement.
func BenchmarkHashReader(b *testing.B) {
	data, err := os.ReadFile(benchJPEG)
	if err != nil {
		b.Fatalf("read %s: %v", benchJPEG, err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		br := bufio.NewReaderSize(bytes.NewReader(data), 1<<16)
		if _, err := HashReader(br); err != nil {
			b.Fatalf("HashReader: %v", err)
		}
	}
}

// BenchmarkHashBytes measures the slice-based parser; no bufio, every h.Write
// is a sub-slice of the caller's buffer. Compare with BenchmarkHashReader to
// see how much of HashReader's cost is the bufio fill memcopy.
func BenchmarkHashBytes(b *testing.B) {
	data, err := os.ReadFile(benchJPEG)
	if err != nil {
		b.Fatalf("read %s: %v", benchJPEG, err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		if _, err := HashBytes(data); err != nil {
			b.Fatalf("HashBytes: %v", err)
		}
	}
}

// BenchmarkSHA256Baseline hashes the full file with stdlib SHA-256 and no
// JPEG parsing. The gap between this and BenchmarkHashReader is the cost of
// the marker walker plus the entropy-scan FF-handling loop.
func BenchmarkSHA256Baseline(b *testing.B) {
	data, err := os.ReadFile(benchJPEG)
	if err != nil {
		b.Fatalf("read %s: %v", benchJPEG, err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		h := sha256.New()
		if _, err := io.Copy(h, bytes.NewReader(data)); err != nil {
			b.Fatalf("sha256: %v", err)
		}
		_ = h.Sum(nil)
	}
}
