package jpghash

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// expectedDigest pins the SHA-256 output for synthBaseline. Changing the
// hashing algorithm in a way that alters the bytes fed to the hasher will
// break this test — that is the point. If the change is intentional,
// rebaseline this constant in the same commit so the digest shift is
// visible in the diff.
const expectedDigest = "eb0e93f1438f805650e4df435784503c19ffa5ab9e040f37c32d50f6ffd277a4"

func TestEqualImagesHashEqually(t *testing.T) {
	a := synthBaselineWithAPP1(t, 64)
	b := synthBaselineWithAPP1(t, 4096)
	if len(a) == len(b) {
		t.Fatalf("test setup: APP1-injected fixtures should differ in length, got %d == %d", len(a), len(b))
	}

	ha, err := HashBytes(a)
	if err != nil {
		t.Fatalf("HashBytes(a): %v", err)
	}
	hb, err := HashBytes(b)
	if err != nil {
		t.Fatalf("HashBytes(b): %v", err)
	}
	if ha != hb {
		t.Fatalf("hashes differ:\n  small APP1 -> %s\n  large APP1 -> %s", ha, hb)
	}
	t.Logf("image hash: %s", ha)
}

func TestKnownDigest(t *testing.T) {
	got, err := HashBytes(synthBaseline(t))
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	if got != expectedDigest {
		t.Fatalf("digest changed:\n  got:  %s\n  want: %s", got, expectedDigest)
	}
}

func TestHashBytesMatchesHashReader(t *testing.T) {
	data := synthBaseline(t)

	gotBytes, err := HashBytes(data)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	gotReader, err := HashReader(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatalf("HashReader: %v", err)
	}
	if gotBytes != gotReader {
		t.Fatalf("HashBytes and HashReader disagree:\n  HashBytes:  %s\n  HashReader: %s", gotBytes, gotReader)
	}
}

func TestHashFileViaTempDir(t *testing.T) {
	data := synthBaseline(t)
	path := filepath.Join(t.TempDir(), "synth.jpg")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile %s: %v", path, err)
	}
	if got != expectedDigest {
		t.Fatalf("HashFile digest differs from pinned:\n  got:  %s\n  want: %s", got, expectedDigest)
	}
}

func TestNoErrorOnRestartMarkersAndFillBytes(t *testing.T) {
	if _, err := HashBytes(synthWithRestartMarkers(t)); err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
}

func TestNoErrorOnMalformedTail(t *testing.T) {
	data := synthMalformedTail(t)

	gotBytes, err := HashBytes(data)
	if err != nil {
		t.Fatalf("HashBytes (malformed tail): %v", err)
	}
	gotReader, err := HashReader(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatalf("HashReader (malformed tail): %v", err)
	}
	if gotBytes != gotReader {
		t.Fatalf("HashBytes/HashReader disagree on malformed tail:\n  bytes:  %s\n  reader: %s", gotBytes, gotReader)
	}
}

func TestNoErrorOnTruncated(t *testing.T) {
	data := synthTruncated(t)

	if _, err := HashBytes(data); err != nil {
		t.Fatalf("HashBytes (truncated): %v", err)
	}
	if _, err := HashReader(bufio.NewReader(bytes.NewReader(data))); err != nil {
		t.Fatalf("HashReader (truncated): %v", err)
	}
}

// TestBaselineEntropyContainsFFStuffing guards the synthesizer itself: if a
// future change makes synthBaseline produce a scan with no FF 00 stuffing
// pairs, the fixture stops exercising hashEntropyData's stuffing path. Catch
// that here before it silently weakens the rest of the test suite.
func TestBaselineEntropyContainsFFStuffing(t *testing.T) {
	if !scanContainsFFStuffing(synthBaseline(t)) {
		t.Fatalf("synthBaseline scan contains no FF 00 stuffing — increase noise or change seed")
	}
}
