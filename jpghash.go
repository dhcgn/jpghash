// Package jpghash computes a SHA-256 hash over the decode-relevant parts of a
// JPEG. APP0–APP15 (FFE0–FFEF) and COM (FFFE) payloads are skipped so EXIF /
// XMP / ICC / JFIF / comment differences do not affect the digest.
package jpghash

import (
	"bufio"
	"bytes"
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

// HashBytes returns the JPEG content hash of an in-memory slice. It produces
// the same digest as HashReader on the same bytes but skips bufio: every
// h.Write is a sub-slice of data, with zero copies. Intended for callers who
// already have the bytes (HTTP responses, externally-managed buffers); use
// HashFile or HashReader for streaming sources.
func HashBytes(data []byte) (string, error) {
	h := sha256.New()

	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return "", errors.New("not a JPEG: missing SOI")
	}
	h.Write(data[:2])

	pos := 2
	for {
		if pos >= len(data) {
			return "", errors.New("unexpected EOF looking for marker")
		}
		if data[pos] != 0xFF {
			return "", fmt.Errorf("expected 0xFF marker prefix, got 0x%02X", data[pos])
		}
		pos++
		for pos < len(data) && data[pos] == 0xFF {
			pos++
		}
		if pos >= len(data) {
			return "", errors.New("unexpected EOF after 0xFF")
		}
		marker := data[pos]
		if marker == 0x00 {
			return "", errors.New("stuffed 0xFF 0x00 outside scan")
		}
		pos++

		if marker == 0xD9 {
			h.Write([]byte{0xFF, 0xD9})
			return hex.EncodeToString(h.Sum(nil)), nil
		}

		if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			h.Write([]byte{0xFF, marker})
			continue
		}

		if pos+2 > len(data) {
			return "", fmt.Errorf("short read on length for marker FF%02X", marker)
		}
		lenBytes := data[pos : pos+2]
		segLen := int(binary.BigEndian.Uint16(lenBytes))
		if segLen < 2 {
			return "", fmt.Errorf("invalid segment length %d for marker FF%02X", segLen, marker)
		}
		if pos+segLen > len(data) {
			return "", fmt.Errorf("short read on payload for marker FF%02X", marker)
		}
		payload := data[pos+2 : pos+segLen]
		pos += segLen

		isMetadata := (marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE
		if !isMetadata {
			h.Write([]byte{0xFF, marker})
			h.Write(lenBytes)
			h.Write(payload)
		}

		if marker == 0xDA {
			for {
				rem := data[pos:]
				if len(rem) < 2 {
					return "", errors.New("unexpected EOF in scan data")
				}
				idx := bytes.IndexByte(rem[:len(rem)-1], 0xFF)
				if idx < 0 {
					return "", errors.New("unexpected EOF in scan data")
				}
				next := rem[idx+1]
				if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
					h.Write(rem[:idx+2])
					pos += idx + 2
					continue
				}
				h.Write(rem[:idx])
				pos += idx
				break
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
		peek, err := r.Peek(r.Size())
		if len(peek) < 2 {
			if err != nil {
				return fmt.Errorf("unexpected EOF in scan data: %w", err)
			}
			return errors.New("short read in scan data")
		}
		// Reserve the trailing byte so a hit at the tail of the window still
		// has a following byte to inspect without re-peeking.
		searchEnd := len(peek) - 1
		idx := bytes.IndexByte(peek[:searchEnd], 0xFF)
		if idx < 0 {
			h.Write(peek[:searchEnd])
			if _, err := r.Discard(searchEnd); err != nil {
				return err
			}
			continue
		}
		next := peek[idx+1]
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
			h.Write(peek[:idx+2])
			if _, err := r.Discard(idx + 2); err != nil {
				return err
			}
			continue
		}
		// Segment boundary at peek[idx]; leave FF + next byte for the
		// outer marker reader.
		if idx > 0 {
			h.Write(peek[:idx])
			if _, err := r.Discard(idx); err != nil {
				return err
			}
		}
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
