# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build ./...                                              # build
go test ./...                                               # all tests
go test -run TestEqualImagesHashEqually -v ./...            # single test
go test -bench=. -benchmem ./...                            # benchmarks (synthetic data)
go run ./cmd/jpghash <path-to-jpeg>                         # run the CLI
```

Go 1.26+ required (see `go.mod`). Stdlib only — no module downloads.

## Architecture

The tool hashes the **decode-relevant** parts of a JPEG and intentionally drops metadata, so EXIF/XMP/ICC differences don't change the digest.

Two packages:

- Root `package jpghash` (`jpghash.go`) — the library. Exports `HashFile(path)`, `HashReader(*bufio.Reader)`, `HashBytes([]byte)`. Callers using `HashReader` pass a `*bufio.Reader` so a wrapping `io.TeeReader` can guarantee every byte the parser sees (including bufio look-ahead) is also visible to the tee — this is what lets a consumer compute a full-file SHA-256 in the same pass.
- `cmd/jpghash/main.go` — the CLI; thin wrapper that calls `jpghash.HashFile`.

### One parser, two input modes

`HashReader` and `HashBytes` are 1-line wrappers over `hashJPEG(*source)`. The `source` struct is a small concrete (not interface) abstraction with `peek(n)`, `peekMax()`, `consume(n)` — slice mode is zero-copy, reader mode goes through `bufio.Peek`/`Discard`. **There is exactly one JPEG state machine in the codebase.** Any change to marker handling, segment hashing, or entropy-scan logic happens in one place.

### Parser flow (`hashJPEG`)

1. **SOI check** — only error path. Missing/invalid `FF D8` returns `"not a JPEG: missing SOI"`.
2. **Marker walk** — `peekMax`, require `FF`, skip fill-byte run, read marker byte. Standalone markers (TEM, RST0–7 between segments) and EOI hash `[FF, marker]` and continue/finalize. Segment markers consume the prefix, peek `segLen` bytes, hash `[FF, marker] + payload` for non-metadata segments. Metadata payloads (APP0–APP15, COM) are dropped via `isMetadata(marker)` — single source of truth for "what counts as metadata."
3. **Entropy scan** (`scanEntropy`) — after an `SOS` (`FFDA`) segment, streams raw bitstream bytes until the next real segment marker. The non-obvious rules:
   - `FF 00` → byte stuffing, hash both
   - `FF (FF)* Dn` → inline RSTn (optionally with leading fill bytes), hash all
   - `FF (FF)* X` (other marker) → real segment boundary; hash everything *before* the FF and return — the FF + fills + marker stay in the source for the outer marker walk
   - `FF (FF)*` ending at the edge of the peek window → return; the outer walk re-peeks with a fresh view to resolve the marker

Max JPEG segment length is 65535. `HashFile` sizes the bufio buffer to 65536 so `peek(segLen)` always returns a full segment in a single call.

### Lenient post-SOI parsing

Once SOI is confirmed, every other parse failure (truncated segment, missing FF-00 byte stuffing in the entropy stream, garbage tail after a phantom marker) returns the partial hash with a nil error via the local `finalize()` closure. Only missing/invalid SOI fails. Cameras and editors (notably DxO DeepPRIME) emit mildly-malformed JPEGs that strict parsers reject; this keeps content-addressed hashes stable for the parseable prefix. **If you add new error-return sites in `hashJPEG`, route them through `finalize()` rather than returning a non-nil error.**

## Test fixtures

All fixtures are **synthesized in memory at test time** from `synth_test.go`. No JPEG files are committed. Builders use a fixed PRNG seed so output is byte-stable, which lets `TestKnownDigest` pin a constant.

The four builders:

- `synthBaseline` — 64×64 seeded-noise image run through `image/jpeg.Encode` (quality 75). Baseline (SOF0), no APP segments. Canonical fixture for the pinned-digest test.
- `synthBaselineWithAPP1(payloadLen)` — `synthBaseline` with an APP1 segment of the requested payload length spliced in right after the SOI. Two calls with different lengths produce JPEGs that differ **only** in APP1 — the equal-image invariant.
- `synthWithRestartMarkers` — `synthBaseline` with `DRI` and `COM` segments inserted before SOS, plus injected scan bytes (`FF 00`, `FF FF D0`, `FF D1`) that exercise byte stuffing, fill-byte-before-RSTn, and inline RSTn in one fixture. The scan does not need to decode — `jpghash` is a marker walker.
- `synthTruncated` — `synthBaseline` with the trailing `FF D9` stripped. Exercises graceful-EOF in `HashReader`, `HashBytes`, and `hashEntropyData`.

Tests that guard the algorithm:

- `TestEqualImagesHashEqually` — `synthBaselineWithAPP1(64)` and `(4096)` must produce the same digest. Core correctness property.
- `TestKnownDigest` — `HashBytes(synthBaseline())` is pinned to `expectedDigest` in `jpghash_test.go`. Catches accidental byte-level drift from refactors that happen to preserve the equal-images property. **Any change that alters the bytes fed to SHA-256 will break this. If the change is intentional, rebaseline the constant in the same commit so the digest shift shows up in the diff.**
- `TestHashBytesMatchesHashReader` — both APIs agree byte-for-byte on the same input.
- `TestHashFileViaTempDir` — writes `synthBaseline` to `t.TempDir()` and re-hashes through `HashFile`, covering `os.Open` + bufio wiring.
- `TestNoErrorOnRestartMarkersAndFillBytes` / `TestNoErrorOnTruncated` — exercise the no-error paths.
- `TestBaselineEntropyContainsFFStuffing` — sanity check on the synthesizer; fails if the fixture stops covering the stuffing path.

## Release pipeline

- `.github/workflows/build.yml` — push/PR on `main`, matrix on `ubuntu-latest` + `windows-latest`, runs `go build` + `go test`.
- `.github/workflows/release.yml` — triggered by `v*` tag push. One Ubuntu runner cross-compiles four binaries (linux amd64/arm64, windows amd64, darwin arm64) from `./cmd/jpghash` with `CGO_ENABLED=0 -trimpath -ldflags='-s -w'`, then `softprops/action-gh-release@v2` attaches them to a generated release. Artifact names use the pattern `jpghash-<tag>-<os>-<arch>[.exe]`. **The build path must be `./cmd/jpghash` — building `.` produces a non-executable package archive.**
