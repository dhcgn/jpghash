package jpghash

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// benchData is a multi-MB synthetic JPEG built once and reused by all
// benchmarks so each iteration measures parsing/hashing — not synthesis.
var (
	benchDataOnce sync.Once
	benchData     []byte
)

func loadBenchData(tb testing.TB) []byte {
	benchDataOnce.Do(func() {
		img := synthImage(synthBenchWidth, synthBenchHt, synthSeed)
		benchData = synthEncode(tb, img, synthQuality)
	})
	return benchData
}

// BenchmarkHashFile measures end-to-end throughput including os.Open and
// buffered I/O — i.e. what a CLI invocation actually pays. The synthetic
// JPEG is materialized to a temp file once outside the timed loop.
func BenchmarkHashFile(b *testing.B) {
	data := loadBenchData(b)
	path := filepath.Join(b.TempDir(), "bench.jpg")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		b.Fatalf("write %s: %v", path, err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()

	for b.Loop() {
		if _, err := HashFile(path); err != nil {
			b.Fatalf("HashFile: %v", err)
		}
	}
}

// BenchmarkHashReader isolates the parser + hasher by serving bytes from
// memory, removing disk I/O from the measurement.
func BenchmarkHashReader(b *testing.B) {
	data := loadBenchData(b)
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
	data := loadBenchData(b)
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
	data := loadBenchData(b)
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
