# CardHashDemo — Design Spec
**Date:** 2026-06-11  
**Author:** Yarden Kantor  
**Status:** Approved

---

## Overview

Educational C# console application demonstrating why SHA1 (and SHA256) are dangerously weak for hashing credit card numbers (PANs / Track 2 data). The demo generates a real Israeli card number, hashes it, then brute-forces the hash live — showing exact elapsed time. A second GPU-accelerated app does the same with ILGPU/CUDA for comparison on NVIDIA hardware.

**Intended audience:** Security engineers, developers handling payment data.  
**Scope:** Educational / authorized security testing only.

---

## Solution Structure

```
C:\git\CardHashDemo\
├── CardHashDemo.sln
├── CardHashDemo.Core\            .NET 10 class library (zero GPU deps)
│   ├── ConsoleHelper.cs
│   ├── SHA1Explainer.cs
│   ├── LuhnAlgorithm.cs
│   ├── IsraeliCards.cs
│   └── HashCracker.cs
├── CardHashDemo.Cpu\             .NET 10 console app
│   └── Program.cs
└── CardHashDemo.Gpu\             .NET 10 console app
    ├── CardHashDemo.Gpu.csproj   (+ ILGPU + ILGPU.Runtime.Cuda NuGet)
    └── Program.cs
```

- **CPU app** has no GPU dependency — runs on any machine including Intel-only laptops.
- **GPU app** requires an NVIDIA CUDA-capable GPU; crashes gracefully on launch if none is present.
- Intel integrated graphics is not used by either app.

---

## Demo Flow (identical in both apps)

### 1. Banner + disclaimer
Colored ASCII banner. Red warning: educational use / authorized testing only.

### 2. SHA1 section
- What SHA1 is: 160-bit digest, designed 1995, fast by design, deterministic
- SHAttered collision attack (2017) — briefly mentioned
- Core problem for card data: no salt, small input space, extremely fast to compute

### 3. Luhn algorithm section
- "Mod 10" algorithm (ISO/IEC 7812)
- Purpose: detect transcription errors, not security
- Live validation demo on a known-good number
- Explains: last digit is fully determined by the preceding 15 digits → only 10^9 free combinations per BIN

### 4. Israeli card BIN section
- Prints the list of ~15 known Israeli BINs (issuer + 6-digit prefix)
- Explains how knowing "Israeli card" collapses 10^16 → ~10^9 per BIN

### 5. SHA1(PAN) attack
- Randomly picks a BIN from the list, generates a valid 16-digit card
- Displays hash: `SHA1(PAN) = <40-hex-chars>`
- 2-second speed benchmark printed first
- Live brute-force: all 10^9 combinations for that BIN
- On find: prints card + elapsed + speed

### 6. SHA256(PAN) attack — no salt
- Same card, SHA256, no salt
- Prints elapsed + speed

### 7. SHA256(static_salt + PAN) attack
- Hardcoded salt bytes (e.g. `"MySuperSecretPepper"`) baked into code
- Explanation: attacker who has the source/binary knows the salt — prepend it to every candidate, same speed
- Crack runs; prints elapsed (barely slower than unsalted)

### 8. SHA256(random_salt + PAN) attack — per-card salt stored in DB
- Random 16-byte salt generated alongside the hash and "stored in DB"
- Explanation: attacker who stole the DB row has both hash AND salt — still full-speed brute force
- Crack runs with the known per-card salt; prints elapsed
- Key message: **salt defeats rainbow tables, not brute force**. The fix is a slow KDF.

### 9. Side-by-side comparison table
```
Algorithm                    | Elapsed      | Speed
─────────────────────────────┼──────────────┼──────────────
SHA1  (no salt)              | HH:MM:SS.ms  | XX.X M/sec
SHA256 (no salt)             | HH:MM:SS.ms  | XX.X M/sec
SHA256 (static salt)         | HH:MM:SS.ms  | XX.X M/sec
SHA256 (per-card random salt)| HH:MM:SS.ms  | XX.X M/sec
─────────────────────────────┴──────────────┴──────────────
None of the above are safe. Use Argon2id/bcrypt.
```

### 8. SHA1(Track2) section (explanation only, no live crack)
- Track 2 format: `;PAN=YYMM SC DISC?`
- Expanded search space calculation: PAN × expiry dates × service codes ≈ 10^11–10^12
- Shows it is still crackable (GPU seconds; CPU hours)
- Notes expiry leakage reduces space further

### 9. Takeaways
- Use tokenization (vault), not hashing, for card data
- If hashing is unavoidable: Argon2id/bcrypt with salt and work factor
- PCI-DSS DSS v4.0 requirements briefly referenced

---

## Core Library — Component Design

### `LuhnAlgorithm.cs`
```csharp
static bool Validate(ReadOnlySpan<char> pan)
static int ComputeCheckDigit(ReadOnlySpan<byte> partialAsciiDigits)
```
Operates on ASCII byte spans — no string allocations. Check digit computed via standard mod-10 doubling from right.

### `IsraeliCards.cs`
```csharp
record BinEntry(string Prefix, string Issuer, int CardLength = 16);
static IReadOnlyList<BinEntry> KnownBins { get; }
static string GenerateCard(BinEntry bin)   // random valid Luhn card
static BinEntry? DetectIsraeli(string pan) // null if not Israeli
```
BIN list (~15 entries) covering Max, Hapoalim, Leumi, Discount, Mizrahi, CAL, Amex IL, Diners IL.

### `HashCracker.cs`
```csharp
record CrackResult(string? Card, TimeSpan Elapsed, long Tried, long Total, double HashesPerSecond);
record CrackProgress(long Tried, long Total, TimeSpan Elapsed);

enum SaltMode { None, Static, PerCard }

static Task<CrackResult> CrackAsync(
    string targetHashHex,
    BinEntry bin,
    HashAlgorithmName algorithm,          // SHA1 or SHA256
    SaltMode saltMode,
    byte[]? salt,                         // null for None; static bytes for Static; per-card bytes for PerCard
    IProgress<CrackProgress>? progress,
    CancellationToken ct);
```

Inner loop (zero allocation per iteration):
1. Reconstruct card bytes from index `i` via integer division — no `ToString`
2. Compute Luhn check digit into last byte
3. Prepend salt bytes if `SaltMode != None` (stack-allocated concat buffer)
4. `SHA1.HashData(input, hashSpan)` or `SHA256.HashData(...)` — .NET 10 intrinsics
5. 20/32-byte span compare against target
5. `Parallel.For` with `MaxDegreeOfParallelism = Environment.ProcessorCount`
6. Progress sampled every 500 K iterations (atomic counter, no lock)
7. `ParallelLoopState.Stop()` on match

### `ConsoleHelper.cs`
Colored banners, section headers, result printing. Unicode box-drawing characters. `.Pause()` for interactive steps.

---

## GPU App — ILGPU Kernel Design

NuGet: `ILGPU` + `ILGPU.Runtime.Cuda`

**Kernel signature:**
```csharp
static void CrackKernel(
    Index1D index,
    ArrayView<byte> binBytes,
    ArrayView<byte> targetHash,
    ArrayView<long> foundIndex,
    long batchOffset,
    int cardLength,
    int algorithmId)   // 0=SHA1, 1=SHA256
```

**Execution:**
- Grid: 65 536 blocks × 256 threads = 16 777 216 candidates per launch
- Relaunch until `foundIndex[0] != -1` or all combinations exhausted
- SHA1 and SHA256 implemented as pure arithmetic inside the kernel (standard FIPS implementations)
- `Interlocked.CompareExchange` on `foundIndex[0]` for first-match write

**On GPU init failure:** catch `CudaException` / `AcceleratorException` at startup, print human-readable error, exit with code 1.

---

## Timing Output Format (both apps)

```
[RESULT] Card found   : 4362011234567894
[RESULT] BIN          : 436201 — Hapoalim Visa
[RESULT] Algorithm    : SHA1 (no salt)
[RESULT] Elapsed      : 00:00:23.417
[RESULT] Speed        : 42.7 M hash/sec
[RESULT] Combinations : 1,000,000,000

[RESULT] Card found   : 4362011234567894
[RESULT] Algorithm    : SHA256 (no salt)
[RESULT] Elapsed      : 00:00:41.103
[RESULT] Speed        : 24.3 M hash/sec

[RESULT] Card found   : 4362011234567894
[RESULT] Algorithm    : SHA256 (static salt "MySuperSecretPepper")
[RESULT] Elapsed      : 00:00:42.881
[RESULT] Speed        : 23.3 M hash/sec
[RESULT] Salt known   : YES (in source code)

[RESULT] Card found   : 4362011234567894
[RESULT] Algorithm    : SHA256 (random per-card salt, stored in DB)
[RESULT] Elapsed      : 00:00:43.210
[RESULT] Speed        : 23.1 M hash/sec
[RESULT] Salt known   : YES (attacker has the DB row)

──────────────────────────────────────────────────────────────────
Algorithm                     │ Elapsed      │ Speed
──────────────────────────────┼──────────────┼──────────────────
SHA1  (no salt)               │ 00:00:23.417 │ 42.7 M/sec
SHA256 (no salt)              │ 00:00:41.103 │ 24.3 M/sec
SHA256 (static salt)          │ 00:00:42.881 │ 23.3 M/sec
SHA256 (per-card random salt) │ 00:00:43.210 │ 23.1 M/sec
──────────────────────────────────────────────────────────────────
Salt defeats rainbow tables. It does NOT defeat brute force.
The fix: use Argon2id or bcrypt with a work factor.
```

---

## Israeli BIN List (initial, approximate — for educational use)

| Prefix | Issuer                          | Length |
|--------|---------------------------------|--------|
| 436201 | Bank Hapoalim Visa              | 16     |
| 464100 | Bank Hapoalim Visa Platinum     | 16     |
| 470640 | Bank Hapoalim Visa Gold         | 16     |
| 492840 | Bank Leumi Visa                 | 16     |
| 431195 | Bank Leumi Visa Classic         | 16     |
| 479614 | Discount Bank Visa              | 16     |
| 457946 | Discount Bank Visa Gold         | 16     |
| 454030 | Mizrahi-Tefahot Visa            | 16     |
| 527136 | Max (formerly Leumi Card) MC    | 16     |
| 526568 | Max Mastercard                  | 16     |
| 535840 | Max Mastercard Platinum         | 16     |
| 527141 | CAL Mastercard                  | 16     |
| 526586 | Isracard Mastercard             | 16     |
| 376818 | American Express Israel         | 15     |
| 304920 | Diners Club Israel              | 14     |

---

## Non-Goals

- No actual real card data used anywhere
- No network connectivity
- No PCI-DSS scoped environment assumed
- GPU app is not expected to fall back to CPU if no CUDA device found (fails fast instead)
