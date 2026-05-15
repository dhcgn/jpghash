// Package jpghash computes a SHA-256 hash over the decode-relevant parts of a
// JPEG. APP0–APP15 (FFE0–FFEF) and COM (FFFE) payloads are skipped so EXIF /
// XMP / ICC / JFIF / comment differences do not affect the digest.
//
// The parser is lenient: once the SOI is confirmed, any later parse failure
// (truncated segment, unstuffed FF in the scan, garbage tail after a phantom
// marker) returns the partial hash with a nil error instead of failing. This
// keeps content-addressed hashes stable for the parseable prefix of mildly
// malformed JPEGs — many cameras and editors emit such files and viewers
// tolerate them.
//
// HashReader and HashBytes share a single parser implementation (hashJPEG)
// driven by a small source abstraction. The two public entry points exist
// for performance (HashBytes is zero-copy on already-in-memory data; HashReader
// streams via bufio), not because they have different semantics — both produce
// the same digest on the same bytes.
package jpghash

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
)

// HashFile opens path and returns the JPEG content hash. The bufio buffer is
// sized to 65536 (max JPEG segment length + 1) so segment payloads always fit
// in a single peek.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return HashReader(bufio.NewReaderSize(f, 1<<16))
}

// HashReader computes the JPEG content hash from a *bufio.Reader. Callers pass
// a *bufio.Reader (not an io.Reader) so a wrapping io.TeeReader can guarantee
// that every byte bufio fetches — including look-ahead — flows through the
// tee. Bytes after the EOI marker are not consumed; drain the reader if you
// need full-file coverage.
//
// The buffer must be at least 65536 bytes so a max-size JPEG segment (length
// field max = 65535) fits in a single peek. HashFile sizes it correctly.
func HashReader(br *bufio.Reader) (string, error) {
	return hashJPEG(&source{r: br})
}

// HashBytes returns the JPEG content hash of an in-memory slice with zero
// copies: every h.Write is a sub-slice of data. Produces the same digest as
// HashReader on the same bytes. Use HashFile or HashReader for streaming
// sources.
func HashBytes(data []byte) (string, error) {
	return hashJPEG(&source{buf: data})
}

// source unifies slice-backed and reader-backed JPEG inputs behind a tiny
// peek/consume API. Concrete struct (not interface) so methods inline cleanly
// on the slice path. Reader mode if r != nil; slice mode otherwise.
type source struct {
	r   *bufio.Reader
	buf []byte
}

// peek returns up to n bytes from the current position without consuming.
// Reader mode triggers a buffer refill as needed. Returns a slice shorter
// than n at EOF.
func (s *source) peek(n int) []byte {
	if s.r != nil {
		b, _ := s.r.Peek(n)
		return b
	}
	if n > len(s.buf) {
		return s.buf
	}
	return s.buf[:n]
}

// peekMax returns the largest contiguous view available without forcing a
// read beyond the buffer. Slice mode: all remaining bytes. Reader mode: the
// full bufio peek window.
func (s *source) peekMax() []byte {
	if s.r != nil {
		b, _ := s.r.Peek(s.r.Size())
		return b
	}
	return s.buf
}

// consume advances past n bytes. n must be <= what was last peeked.
func (s *source) consume(n int) {
	if s.r != nil {
		s.r.Discard(n) //nolint:errcheck
		return
	}
	s.buf = s.buf[n:]
}

// hashJPEG is the single parser shared by HashReader and HashBytes.
//
// State machine: magic-byte check for SOI, then loop walking markers.
// Standalone markers (TEM, RST0–7 between segments) are written as
// [FF, marker]. EOI ends the hash cleanly. Segment markers read
// [length, payload]; metadata payloads (APP0–APP15, COM) are dropped from
// the hash, everything else is written. After an SOS marker, scanEntropy
// streams the entropy-coded data.
//
// Lenient finalize: post-SOI, every parse hiccup routes through finalize()
// which returns the partial hash with nil error.
func hashJPEG(src *source) (string, error) {
	h := sha256.New()

	// Magic-byte check. Peek 8 so the rejection error can name the actual
	// format (BMP / PNG / etc.) when the extension lies. Only the SOI pair
	// is consumed on success.
	head := src.peek(8)
	if len(head) < 2 || head[0] != 0xFF || head[1] != 0xD8 {
		return "", fmt.Errorf("not a JPEG: %s", describeNonJPEG(head))
	}
	h.Write(head[:2])
	src.consume(2)

	finalize := func() (string, error) {
		return hex.EncodeToString(h.Sum(nil)), nil
	}

	for {
		view := src.peekMax()
		if len(view) < 2 || view[0] != 0xFF {
			return finalize()
		}
		i := 1
		for i < len(view) && view[i] == 0xFF {
			i++
		}
		if i >= len(view) {
			return finalize()
		}
		marker := view[i]
		if marker == 0x00 {
			return finalize() // stuffed FF 00 outside scan
		}

		if marker == 0xD9 { // EOI
			h.Write([]byte{0xFF, 0xD9})
			src.consume(i + 1)
			return finalize()
		}

		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			// Standalone marker: TEM or RSTn between segments. Fill bytes
			// preceding the marker are dropped (spec-allowed prefix, not data).
			h.Write([]byte{0xFF, marker})
			src.consume(i + 1)
			continue
		}

		// Segment marker. Consume the [FF, fills, marker] prefix, then peek
		// [length, payload]. Max segLen = 65535, fits in the 64KB bufio buffer.
		src.consume(i + 1)

		seg := src.peek(2)
		if len(seg) < 2 {
			return finalize()
		}
		segLen := int(binary.BigEndian.Uint16(seg))
		if segLen < 2 {
			return finalize()
		}
		full := src.peek(segLen)
		if len(full) < segLen {
			return finalize()
		}

		if !isMetadata(marker) {
			h.Write([]byte{0xFF, marker})
			h.Write(full[:segLen])
		}
		src.consume(segLen)

		if marker == 0xDA {
			scanEntropy(src, h)
		}
	}
}

// isMetadata reports whether a segment's payload should be excluded from the
// hash: APP0–APP15 and COM. Single source of truth for "what counts as
// metadata"; edit here if e.g. ICC (APP2) or Adobe (APP14) should be hashed.
func isMetadata(marker byte) bool {
	return (marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE
}

// describeNonJPEG names the file format from leading bytes (or echoes them
// as hex when no signature matches), for the magic-byte rejection error.
// Lets callers distinguish a misnamed BMP/PNG/encrypted blob from a real
// broken JPEG when triaging "not a JPEG" logs.
func describeNonJPEG(head []byte) string {
	if len(head) == 0 {
		return "empty file"
	}
	switch {
	case len(head) >= 2 && head[0] == 0x42 && head[1] == 0x4D:
		return "detected BMP"
	case len(head) >= 4 && head[0] == 0x89 && head[1] == 0x50 && head[2] == 0x4E && head[3] == 0x47:
		return "detected PNG"
	case len(head) >= 3 && head[0] == 0x47 && head[1] == 0x49 && head[2] == 0x46:
		return "detected GIF"
	case len(head) >= 4 && head[0] == 0x49 && head[1] == 0x49 && head[2] == 0x2A && head[3] == 0x00:
		return "detected TIFF (little-endian)"
	case len(head) >= 4 && head[0] == 0x4D && head[1] == 0x4D && head[2] == 0x00 && head[3] == 0x2A:
		return "detected TIFF (big-endian)"
	case len(head) >= 4 && head[0] == 0x52 && head[1] == 0x49 && head[2] == 0x46 && head[3] == 0x46:
		return "detected RIFF (WebP/AVI/WAV)"
	case len(head) >= 4 && head[0] == 0x25 && head[1] == 0x50 && head[2] == 0x44 && head[3] == 0x46:
		return "detected PDF"
	case len(head) >= 8 && head[4] == 0x66 && head[5] == 0x74 && head[6] == 0x79 && head[7] == 0x70:
		return "detected ISOBMFF (MP4/HEIC/HEIF)"
	}
	return fmt.Sprintf("unrecognized magic bytes %X", head)
}

// scanEntropy streams compressed scan bytes through h until the next real
// segment marker. The marker boundary (FF + any fill bytes + marker byte) is
// left in the source for the outer marker walk to consume.
//
// In the entropy-coded stream:
//   - FF 00         => byte stuffing; the literal FF is part of the bitstream
//   - FF D0..D7     => inline RSTn restart marker
//   - FF (fill)+ Dn => inline RSTn with leading fill bytes
//   - FF (fill)* X  => real segment boundary; stop, leave for outer walk
func scanEntropy(src *source, h hash.Hash) {
	for {
		view := src.peekMax()
		if len(view) < 2 {
			// Near or at EOF: hash any remaining byte and stop. The outer
			// marker walk will see an empty/short peek and finalize.
			if len(view) > 0 {
				h.Write(view)
				src.consume(len(view))
			}
			return
		}
		// Reserve the trailing byte so any FF hit has at least one successor
		// to inspect without re-peeking.
		searchEnd := len(view) - 1
		idx := bytes.IndexByte(view[:searchEnd], 0xFF)
		if idx < 0 {
			// No FF in the searchable region. Hash everything except the
			// trailing byte and re-peek (the trailing byte will be classified
			// next iteration, or hashed by the len<2 branch at EOF).
			h.Write(view[:searchEnd])
			src.consume(searchEnd)
			continue
		}
		// Walk any fill-byte run after the FF to find the classifying byte.
		markerPos := idx + 1
		for markerPos < len(view) && view[markerPos] == 0xFF {
			markerPos++
		}
		if markerPos >= len(view) {
			// Fill-byte run reaches the edge. Hash up to (not including) the
			// FF and return so the outer marker walk re-peeks with a fresh
			// view that contains the marker byte.
			if idx > 0 {
				h.Write(view[:idx])
				src.consume(idx)
			}
			return
		}
		actual := view[markerPos]
		if actual == 0x00 || (actual >= 0xD0 && actual <= 0xD7) {
			// Byte stuffing or inline RSTn (optionally preceded by fill bytes).
			// All of these bytes are part of the entropy stream; hash them.
			h.Write(view[:markerPos+1])
			src.consume(markerPos + 1)
			continue
		}
		// Real segment marker boundary. Hash up to (not including) the FF;
		// leave the marker prefix in the source for the outer marker walk.
		if idx > 0 {
			h.Write(view[:idx])
			src.consume(idx)
		}
		return
	}
}
