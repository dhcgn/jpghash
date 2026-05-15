package jpghash

import (
	"os"
	"testing"
)

// expectedDigest pins the SHA-256 output for the reference JPEG. Changing
// the hashing algorithm in a way that alters the bytes fed to the hasher
// will break this test — that is the point. If the change is intentional,
// rebaseline this constant in the same commit so the digest shift is
// visible in the diff.
const expectedDigest = "268dcec45b80e7780e38bae9f242570ccf985fa1670cb6e07eb1f34fd9890778"

func TestEqualImagesHashEqually(t *testing.T) {
	a := "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME.jpg"
	b := "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME(1).jpg"

	ha, err := HashFile(a)
	if err != nil {
		t.Fatalf("hash %s: %v", a, err)
	}
	hb, err := HashFile(b)
	if err != nil {
		t.Fatalf("hash %s: %v", b, err)
	}
	if ha != hb {
		t.Fatalf("hashes differ:\n  %s -> %s\n  %s -> %s", a, ha, b, hb)
	}
	t.Logf("image hash: %s", ha)
}

func TestKnownDigest(t *testing.T) {
	path := "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME.jpg"
	got, err := HashFile(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	if got != expectedDigest {
		t.Fatalf("digest changed:\n  got:  %s\n  want: %s", got, expectedDigest)
	}
}

func TestHashBytesMatchesPinned(t *testing.T) {
	path := "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME.jpg"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	got, err := HashBytes(data)
	if err != nil {
		t.Fatalf("HashBytes: %v", err)
	}
	if got != expectedDigest {
		t.Fatalf("HashBytes digest differs from streaming digest:\n  got:  %s\n  want: %s", got, expectedDigest)
	}
}
