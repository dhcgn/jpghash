package main

import "testing"

func TestEqualImagesHashEqually(t *testing.T) {
	a := "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME.jpg"
	b := "test-data/equal-image/DSC_3264-NEF_DxO_DeepPRIME(1).jpg"

	ha, err := hashJPEGImage(a)
	if err != nil {
		t.Fatalf("hash %s: %v", a, err)
	}
	hb, err := hashJPEGImage(b)
	if err != nil {
		t.Fatalf("hash %s: %v", b, err)
	}
	if ha != hb {
		t.Fatalf("hashes differ:\n  %s -> %s\n  %s -> %s", a, ha, b, hb)
	}
	t.Logf("image hash: %s", ha)
}
