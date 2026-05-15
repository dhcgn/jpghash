# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build ./...                                              # build
go test ./...                                               # all tests
go test -run TestEqualImagesHashEqually -v ./...            # single test
go run ./cmd/jpghash <path-to-jpeg>                         # run the CLI
```

Go 1.26+ required (see `go.mod`). Stdlib only — no module downloads.

## Architecture

The tool hashes the **decode-relevant** parts of a JPEG and intentionally drops metadata, so EXIF/XMP/ICC differences don't change the digest.

Two packages:

- Root `package jpghash` (`jpghash.go`) — the library. Exports `HashFile(path)` and `HashReader(*bufio.Reader)`. Callers pass a `*bufio.Reader` so a wrapping `io.TeeReader` can guarantee every byte the parser sees (including bufio look-ahead) is also visible to the tee — this is what lets a consumer compute a full-file SHA-256 in the same pass.
- `cmd/jpghash/main.go` — the CLI; thin wrapper that calls `jpghash.HashFile`.

The interesting flow is in `HashReader`:

1. **Marker walker** — reads `FF <marker>` pairs, then a 2-byte big-endian length and payload. APP0–APP15 (`FFE0`–`FFEF`) and COM (`FFFE`) payloads are **dropped**; everything else (`SOF*`, `DQT`, `DHT`, `DRI`, `SOS`) is fed to SHA-256.
2. **Entropy-coded scan** — after an `SOS` (`FFDA`) segment, `hashEntropyData` streams raw bitstream bytes until it sees the next real segment marker. The non-obvious rules it implements:
   - `FF 00` → byte stuffing, hash both
   - `FF D0..D7` → inline `RSTn` restart marker, hash both
   - `FF FF` or `FF <other>` → segment boundary; **leave both bytes in the reader** (uses `bufio.Peek(2)` so nothing is consumed) and return to the outer walker
3. **Marker reader** — `readMarker` consumes `FF` plus any run of `FF` fill bytes, then returns the first non-`FF` byte as the marker.

If you change the metadata-skip predicate (e.g. to include ICC profile / APP2 or Adobe APP14 in the hash), edit the `isMetadata` check in `HashReader`. That's the single source of truth for "what counts as metadata."

## Test-data invariant

`test-data/equal-image/` holds two JPEGs that differ **only** in EXIF (sizes 16,858,534 vs 16,870,579 bytes; APP1 lengths 1123 vs 13168). `TestEqualImagesHashEqually` asserts both files produce the identical digest — this is the core correctness check for the whole tool. Any change to the hashing algorithm must keep this test green, and changes that affect the digest will rebaseline it for everyone (the digest is not pinned, only equality between the two files is checked).

## Release pipeline

- `.github/workflows/build.yml` — push/PR on `main`, matrix on `ubuntu-latest` + `windows-latest`, runs `go build` + `go test`.
- `.github/workflows/release.yml` — triggered by `v*` tag push. One Ubuntu runner cross-compiles four binaries (linux amd64/arm64, windows amd64, darwin arm64) from `./cmd/jpghash` with `CGO_ENABLED=0 -trimpath -ldflags='-s -w'`, then `softprops/action-gh-release@v2` attaches them to a generated release. Artifact names use the pattern `jpghash-<tag>-<os>-<arch>[.exe]`. **The build path must be `./cmd/jpghash` — building `.` produces a non-executable package archive.**
