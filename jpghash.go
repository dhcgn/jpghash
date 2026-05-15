// Package jpghash computes a SHA-256 hash over the decode-relevant parts of a
// JPEG. APP0–APP15 (FFE0–FFEF) and COM (FFFE) payloads are skipped so EXIF /
// XMP / ICC / JFIF / comment differences do not affect the digest.
package jpghash

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

// HashFile opens path and returns the JPEG content hash.
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
func HashReader(br *bufio.Reader) (string, error) {
	h := sha256.New()

	soi, err := readN(br, 2)
	if err != nil || soi[0] != 0xFF || soi[1] != 0xD8 {
		return "", errors.New("not a JPEG: missing SOI")
	}
	h.Write(soi)

	for {
		marker, err := readMarker(br)
		if err != nil {
			return "", err
		}

		if marker == 0xD9 { // EOI
			h.Write([]byte{0xFF, 0xD9})
			return hex.EncodeToString(h.Sum(nil)), nil
		}

		// Standalone markers (no length, no payload). Not expected here in
		// well-formed files, but cheap to handle.
		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			h.Write([]byte{0xFF, marker})
			continue
		}

		lenBytes, err := readN(br, 2)
		if err != nil {
			return "", fmt.Errorf("short read on length for marker FF%02X: %w", marker, err)
		}
		segLen := int(binary.BigEndian.Uint16(lenBytes))
		if segLen < 2 {
			return "", fmt.Errorf("invalid segment length %d for marker FF%02X", segLen, marker)
		}
		payload, err := readN(br, segLen-2)
		if err != nil {
			return "", fmt.Errorf("short read on payload for marker FF%02X: %w", marker, err)
		}

		isMetadata := (marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE
		if !isMetadata {
			h.Write([]byte{0xFF, marker})
			h.Write(lenBytes)
			h.Write(payload)
		}

		if marker == 0xDA {
			if err := hashEntropyData(br, h); err != nil {
				return "", err
			}
		}
	}
}

// hashEntropyData streams compressed scan bytes through h until it sees the
// next real segment marker, which it leaves untouched in the reader for the
// outer loop to consume.
//
// In the entropy-coded stream:
//   - FF 00         => byte stuffing (literal FF in the bitstream)
//   - FF D0..D7     => inline RSTn restart marker
//   - FF FF         => the first FF is a fill byte preceding a marker; stop
//   - FF <other>    => start of next segment; stop
func hashEntropyData(r *bufio.Reader, h hash.Hash) error {
	for {
		peek, err := r.Peek(2)
		if err != nil {
			return fmt.Errorf("unexpected EOF in scan data: %w", err)
		}
		if peek[0] != 0xFF {
			b, _ := r.ReadByte()
			h.Write([]byte{b})
			continue
		}
		b1, b2 := peek[0], peek[1]
		if b2 == 0x00 || (b2 >= 0xD0 && b2 <= 0xD7) {
			if _, err := r.Discard(2); err != nil {
				return err
			}
			h.Write([]byte{b1, b2})
			continue
		}
		// b2 is either 0xFF (fill byte before a marker) or a real marker byte.
		// Either way we're at a segment boundary — leave both bytes for the
		// outer marker reader.
		return nil
	}
}

// readMarker consumes 0xFF followed by any number of 0xFF fill bytes and
// returns the first non-0xFF byte as the marker.
func readMarker(r *bufio.Reader) (byte, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("unexpected EOF looking for marker: %w", err)
	}
	if first != 0xFF {
		return 0, fmt.Errorf("expected 0xFF marker prefix, got 0x%02X", first)
	}
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("unexpected EOF after 0xFF: %w", err)
		}
		if b == 0xFF {
			continue
		}
		if b == 0x00 {
			return 0, errors.New("stuffed 0xFF 0x00 outside scan")
		}
		return b, nil
	}
}

func readN(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
