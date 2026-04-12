# Performance Report (2026-04-12)

This report summarizes handshake-path and GRO-path performance work done in this branch, with benchmark evidence.

## Scope

- `tun/offload_linux.go`: remove duplicate flow-key map lookups on GRO table misses.
- `device/send.go`: eliminate handshake packet/slice wrapper allocations in send path.
- `device/noise-helpers.go`: optimize HMAC/KDF allocation behavior (pooling + static HKDF constants).
- `device/noise-protocol.go`: make `mixHash` allocation-free via pooled BLAKE2s hash state.
- `device/noise-protocol.go`: add in-place handshake constructors (`CreateMessageInitiationInto`, `CreateMessageResponseInto`) to enable stack-owned callsites.
- `device/cookie.go`: reuse keyed BLAKE2s-128 hash state in cookie MAC paths to avoid per-call hash object allocations.
- `device/logger.go` + `device/send.go`: add fast verbosity flag checks so silent verbose logs do not pay variadic argument conversion cost on handshake hot paths.
- `device/noise-helpers.go`: switch X25519 keygen/shared-secret implementation from `golang.org/x/crypto/curve25519` calls to `github.com/cloudflare/circl/dh/x25519` fixed-size key APIs to remove crypto-side heap churn.
- `device/indextable.go`: replace `sync.Map` with `map+RWMutex` to reduce index-path allocations.
- `device/*_bench_test.go`: add focused benchmark coverage for attribution.

## Key Results

### End-to-end handshake initiation

`go test ./device -run='^$' -bench='BenchmarkSendHandshakeInitiation$' -benchmem`

- Baseline (early run): `6908 B/op`, `72 allocs/op`
- After all optimizations: `~1192 B/op`, `20 allocs/op`
- Net: `-5716 B/op` and `-52 allocs/op` (about `-83%` bytes/op and `-72%` allocs/op)

### Isolated create-init path

`go test ./device -run='^$' -bench='BenchmarkCreateMessageInitiation$' -benchmem`

- Before index/KDF constant refinements: `885 B/op`, `24 allocs/op`
- After refinements: `800 B/op`, `16 allocs/op`
- Net: `-85 B/op`, `-8 allocs/op`

### Crypto microbenchmarks

`go test ./device -run='^$' -bench='Benchmark(HMAC1|HMAC2|KDF2|MixHash)$' -benchmem`

- `BenchmarkHMAC1`: `160 B/op, 3 allocs/op` -> `0 B/op, 0 allocs/op`
- `BenchmarkHMAC2`: `160 B/op, 3 allocs/op` -> `0 B/op, 0 allocs/op`
- `BenchmarkKDF2`: `514 B/op, 12 allocs/op` -> `32 B/op, 1 allocs/op`
- `BenchmarkMixHash`: now `0 B/op, 0 allocs/op`

### Attribution benchmarks (where time/allocs remain)

`go test ./device -run='^$' -bench='BenchmarkCreateMessageInitiation(FixedEphemeral|FixedEphemeralPrecomputedAEAD)?$' -benchmem`

- `BenchmarkCreateMessageInitiation`: `~90 us/op`, `800 B/op`, `16 allocs/op`
- `BenchmarkCreateMessageInitiationFixedEphemeral`: `~4.47 us/op`, `288 B/op`, `5 allocs/op`
- `BenchmarkCreateMessageInitiationFixedEphemeralPrecomputedAEAD`: `~0.48 us/op`, `176 B/op`, `2 allocs/op`

Interpretation:

- Most runtime in full create-init is curve25519/ECDH/keygen.
- Most non-crypto allocation overhead has been removed.
- Remaining floor is mainly structural/bookkeeping plus unavoidable crypto object behavior.

### Cookie/MAC path improvement impact

After cookie hash-state reuse (`device/cookie.go`):

- `BenchmarkSendHandshakeInitiation`: `1192 B/op, 20 allocs/op` -> `1000 B/op, 19 allocs/op`
- `BenchmarkCreateMessageInitiation`: unchanged (`800 B/op, 16 allocs/op`), as expected (cookie MAC work is outside pure create-init).

### Logging hot-path improvement impact

After adding explicit `log.verbose` branch checks around handshake verbose logs:

- `BenchmarkSendHandshakeInitiation`: `1000 B/op, 19 allocs/op` -> `984 B/op, 18 allocs/op`

This is a small but reliable reduction from avoiding varargs/interface conversion when verbose logging is disabled.

### X25519 backend change impact

After switching to CIRCL X25519 fixed-key APIs:

- `BenchmarkCreateMessageInitiation`: `800 B/op, 16 allocs/op` -> `288 B/op, 5 allocs/op`
- `BenchmarkSendHandshakeInitiation`: `984 B/op, 18 allocs/op` -> `472 B/op, 7 allocs/op`

This is the largest allocation drop in the series and exceeds the "cut ~5 allocs" target on both paths.

## Additional API Improvement

In-place constructors were added and the send path now uses them:

- `CreateMessageInitiationInto(peer, *MessageInitiation)`
- `CreateMessageResponseInto(peer, *MessageResponse)`
- send path updated in `device/send.go` to construct handshake messages in caller-owned stack variables.

The existing pointer-returning APIs are retained as wrappers for compatibility with tests and other callsites.

## Repro Commands

```bash
go test ./device
go test ./device -run='^$' -bench='BenchmarkSendHandshakeInitiation$' -benchmem -count=3
go test ./device -run='^$' -bench='BenchmarkCreateMessageInitiation(FixedEphemeral|FixedEphemeralPrecomputedAEAD)?$' -benchmem -count=3
go test ./device -run='^$' -bench='Benchmark(HMAC1|HMAC2|KDF2|MixHash)$' -benchmem -count=3
go test ./tun
```

## Notes

- Benchmarks were run on `darwin/arm64` (Apple M3). Absolute ns/op values are machine-dependent.
- Allocation trends (`B/op`, `allocs/op`) were stable and are the primary signal used in this report.
