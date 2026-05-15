package jpghash

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"testing"
)

// Synthetic JPEG builders for tests. All output is deterministic for a given
// seed so the pinned digest in TestKnownDigest stays stable across runs.

const (
	synthSeed       = 1
	synthQuality    = 75
	synthWidth      = 64
	synthHeight     = 64
	synthBenchWidth = 1024
	synthBenchHt    = 1024
)

// synthImage builds a w×h image filled with per-pixel noise from a seeded
// PRNG. High-entropy content keeps the JPEG entropy stream non-degenerate, so
// FF byte stuffing reliably appears in the encoded scan.
func synthImage(w, h int, seed int64) *image.RGBA {
	rng := rand.New(rand.NewSource(seed))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetRGBA(x, y, color.RGBA{
				R: uint8(rng.Intn(256)),
				G: uint8(rng.Intn(256)),
				B: uint8(rng.Intn(256)),
				A: 255,
			})
		}
	}
	return img
}

// synthEncode JPEG-encodes img at the given quality and returns the bytes.
func synthEncode(t testing.TB, img image.Image, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	return buf.Bytes()
}

// synthBaseline returns the canonical synthetic JPEG: 64×64 seeded-noise
// content, baseline (SOF0), no APP segments (Go's stdlib encoder writes
// none). Used by the pinned-digest test.
func synthBaseline(t testing.TB) []byte {
	return synthEncode(t, synthImage(synthWidth, synthHeight, synthSeed), synthQuality)
}

// synthBaselineWithAPP1 returns synthBaseline with an APP1 (EXIF) segment of
// the requested payload length spliced in right after the SOI marker. Two
// calls with different payloadLen values produce JPEGs that differ ONLY in
// the APP1 segment — the equal-image invariant.
func synthBaselineWithAPP1(t testing.TB, payloadLen int) []byte {
	t.Helper()
	base := synthBaseline(t)
	if len(base) < 2 || base[0] != 0xFF || base[1] != 0xD8 {
		t.Fatalf("synthBaseline did not start with SOI")
	}
	segLen := payloadLen + 2 // 2 bytes for the length field itself
	if segLen > 0xFFFF {
		t.Fatalf("APP1 payload too large: %d", payloadLen)
	}
	header := []byte{0xFF, 0xE1, byte(segLen >> 8), byte(segLen & 0xFF)}
	payload := bytes.Repeat([]byte{0xAB}, payloadLen)

	out := make([]byte, 0, len(base)+len(header)+len(payload))
	out = append(out, base[:2]...) // SOI
	out = append(out, header...)
	out = append(out, payload...)
	out = append(out, base[2:]...)
	return out
}

// synthWithRestartMarkers builds a JPEG that exercises every edge case the
// PICA0372 real-world fixture used to cover: DRI segment, COM segment, byte
// stuffing in the scan, a fill byte (FF FF) preceding an inline RSTn, and a
// plain inline RSTn. The scan does not need to decode to a real image —
// jpghash is a marker walker and never invokes a JPEG decoder.
func synthWithRestartMarkers(t testing.TB) []byte {
	t.Helper()
	base := synthBaseline(t)

	sosIdx := bytes.Index(base, []byte{0xFF, 0xDA})
	if sosIdx < 0 {
		t.Fatalf("synthBaseline has no SOS marker")
	}
	sosSegLen := int(binary.BigEndian.Uint16(base[sosIdx+2 : sosIdx+4]))
	sosEnd := sosIdx + 2 + sosSegLen // end of SOS segment header (start of scan data)

	dri := []byte{0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01}
	com := []byte{0xFF, 0xFE, 0x00, 0x07, 'h', 'e', 'l', 'l', 'o'}
	// Scan-test bytes: FF 00 (stuffing), FF FF D0 (fill byte + inline RST0),
	// FF D1 (plain inline RST1). The outer marker walker reads SOS, then
	// hashEntropyData must classify each of these correctly.
	scanInject := []byte{0xFF, 0x00, 0xFF, 0xFF, 0xD0, 0xFF, 0xD1}

	out := make([]byte, 0, len(base)+len(dri)+len(com)+len(scanInject))
	out = append(out, base[:sosIdx]...)
	out = append(out, dri...)
	out = append(out, com...)
	out = append(out, base[sosIdx:sosEnd]...) // SOS header unchanged
	out = append(out, scanInject...)
	out = append(out, base[sosEnd:]...) // original scan + EOI
	return out
}

// synthMalformedTail returns synthBaseline with the trailing EOI replaced by
// a phantom APP2 segment whose payload ends with raw garbage that is not a
// valid marker. Mirrors the real-world DxO DeepPRIME output that triggered
// the lenient-parse change: an FF Ex inside or just after the scan is parsed
// as a metadata segment, and the bytes following it are not a marker. The
// parser should return the hash of everything it parsed successfully and not
// error.
func synthMalformedTail(t testing.TB) []byte {
	t.Helper()
	base := synthBaseline(t)
	if len(base) < 2 || base[len(base)-2] != 0xFF || base[len(base)-1] != 0xD9 {
		t.Fatalf("synthBaseline did not end with EOI")
	}
	trunk := base[:len(base)-2]

	// Phantom APP2: marker + length (12 = 2 length bytes + 10 payload bytes)
	// + 10 payload bytes. Then raw non-marker garbage (no leading FF).
	phantom := []byte{0xFF, 0xE2, 0x00, 0x0C}
	phantom = append(phantom, bytes.Repeat([]byte{0x55}, 10)...)
	garbage := []byte{0x95, 0xA2, 0xB7, 0xE4, 0x7B, 0x31, 0xB9, 0x41}

	out := make([]byte, 0, len(trunk)+len(phantom)+len(garbage))
	out = append(out, trunk...)
	out = append(out, phantom...)
	out = append(out, garbage...)
	return out
}

// synthTruncated returns synthBaseline minus the trailing FF D9 EOI marker.
// Exercises the graceful-EOF path in HashReader / HashBytes / hashEntropyData.
func synthTruncated(t testing.TB) []byte {
	t.Helper()
	base := synthBaseline(t)
	if len(base) < 2 || base[len(base)-2] != 0xFF || base[len(base)-1] != 0xD9 {
		t.Fatalf("synthBaseline did not end with EOI")
	}
	return base[:len(base)-2]
}

// scanContainsFFStuffing reports whether the entropy-coded scan region of
// data contains at least one FF 00 stuffing pair.
func scanContainsFFStuffing(data []byte) bool {
	sosIdx := bytes.Index(data, []byte{0xFF, 0xDA})
	if sosIdx < 0 {
		return false
	}
	if sosIdx+4 > len(data) {
		return false
	}
	segLen := int(binary.BigEndian.Uint16(data[sosIdx+2 : sosIdx+4]))
	scanStart := sosIdx + 2 + segLen
	eoiIdx := bytes.LastIndex(data, []byte{0xFF, 0xD9})
	if eoiIdx < 0 || eoiIdx <= scanStart {
		eoiIdx = len(data)
	}
	return bytes.Contains(data[scanStart:eoiIdx], []byte{0xFF, 0x00})
}
