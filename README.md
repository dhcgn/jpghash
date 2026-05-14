# jpghash

[![Build](https://img.shields.io/github/actions/workflow/status/dhcgn/jpghash/build.yml?branch=main)](https://github.com/dhcgn/jpghash/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/dhcgn/jpghash)](https://github.com/dhcgn/jpghash/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/dhcgn/jpghash)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/dhcgn/jpghash)](https://goreportcard.com/report/github.com/dhcgn/jpghash)
[![Downloads](https://img.shields.io/github/downloads/dhcgn/jpghash/total)](https://github.com/dhcgn/jpghash/releases)

A small Go CLI that prints a SHA-256 hash of a JPEG's **image-relevant bitstream** — the parts of the file that determine the decoded pixels. Metadata-only differences (EXIF, XMP, ICC profile, JFIF header, comments) are stripped before hashing, so two JPEGs with identical image content but different metadata produce the same digest.

## Usage

```
jpghash <path-to-jpeg>
```

Prints a 64-character hex digest to stdout and exits 0. On any error (file missing, not a JPEG, truncated) it prints to stderr and exits 1.

```
$ jpghash photo.jpg
268dcec45b80e7780e38bae9f242570ccf985fa1670cb6e07eb1f34fd9890778
```

## Build

```
go build -o jpghash .
```

Requires Go 1.26+. No external dependencies — stdlib only.

## Test

```
go test ./...
```

The included test hashes the two files under `test-data/equal-image/` (same image, different EXIF) and asserts the digests match.

## What gets hashed

JPEG segments included in the hash:

- `SOI` / `EOI` framing
- `SOF*` — frame headers (dimensions, components, sampling)
- `DQT` — quantization tables
- `DHT` — Huffman tables
- `DRI` — restart interval
- `SOS` header and the entropy-coded scan data that follows (including inline `RSTn` restart markers and `FF 00` byte stuffing)

Segments excluded (treated as metadata):

- `APP0`–`APP15` (`FFE0`–`FFEF`) — JFIF, EXIF, XMP, ICC profile, Adobe, etc.
- `COM` (`FFFE`) — comments

Trailing bytes after `EOI` are ignored.
