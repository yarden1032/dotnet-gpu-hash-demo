# GPU Architecture Notes

This document explains how `CardHashDemo.Gpu` works and why the code looks more
manual than normal C#.

## High-Level Flow

`Program.cs` handles the story of the demo:

1. Detect usable GPU backends and let the user choose one in the terminal.
2. Generate a valid target card.
3. Compute the target hashes on the CPU.
4. Call `GpuCracker.Crack(...)` for each attack.
5. Print timings and write a summary.

`GpuCracker.cs` handles the GPU work:

1. Create an ILGPU `Context`.
2. Create a CUDA or OpenCL `Accelerator`.
3. Copy small input buffers to GPU memory.
4. Compile/load the crack kernel.
5. Launch the kernel in batches.
6. Copy back only the found marker and card result.

## CPU vs GPU Responsibilities

CPU work:

- Choose the BIN.
- Generate the target card.
- Compute the target hash.
- Allocate GPU buffers.
- Launch GPU batches.
- Read back the result after each batch.

GPU work:

- Convert candidate index to card digits.
- Compute the Luhn check digit.
- Build the one-block SHA input.
- Run SHA1 or SHA256.
- Compare the digest to the target hash.
- Store the found card if there is a match.

## Does the Kernel Run Under .NET?

The GPU console app is a normal .NET process, but `CrackKernel(...)` is not
executed by the .NET runtime. ILGPU compiles that C# method into GPU-native
CUDA/OpenCL code, and the GPU driver executes the compiled kernel on the GPU.

That is why the kernel is low-level and avoids normal managed features such as
strings, managed arrays, LINQ, exceptions, and framework cryptography APIs.

## Why Batching Exists

One 16-digit BIN has:

```text
6 fixed BIN digits
9 searched digits
1 deterministic Luhn digit
```

That means `10^9` candidates per BIN. Launching one billion GPU threads in one
call is not practical. The code splits the work into batches:

```csharp
private const int BatchSize = 1 << 24; // 16M candidates
```

Each launch checks up to 16 million candidates. The CPU checks one small marker
after each batch to see whether a match was found.

## Kernel Signature

The kernel method is:

```csharp
private static void CrackKernel(...)
```

Even though it is written in C#, ILGPU compiles it to GPU code. It does not run
like a normal managed C# method.

Important restrictions:

- No `new` managed objects inside the kernel.
- No strings.
- No `List<T>`, LINQ, exceptions, or interfaces.
- No managed arrays.
- Parameters must be GPU-compatible primitive values or `ArrayView` buffers.

## Candidate Index to Card Digits

Each GPU thread receives an `index.X`. The global candidate number is:

```csharp
long candidateIdx = batchOffset + index.X;
```

For example:

```text
candidateIdx = 0  -> 000000000
candidateIdx = 1  -> 000000001
candidateIdx = 42 -> 000000042
```

Those nine digits are placed after the six BIN digits. The final digit is not
searched. It is computed with Luhn.

## SHA Block Packing

SHA1 and SHA256 process 64-byte blocks. The demo inputs are always small:

```text
PAN only:           16 bytes
16-byte salt + PAN: 32 bytes
```

Both fit in one SHA block. The kernel manually builds the 16 big-endian words
`pm0` through `pm15`. This avoids arrays and dynamic memory.

## Found Marker

All threads share:

```csharp
ArrayView1D<int, Stride1D.Dense> foundIndex
ArrayView1D<byte, Stride1D.Dense> foundCard
```

`foundIndex[0] == -1` means no card has been found yet.

When a match is found, the kernel uses:

```csharp
Atomic.CompareExchange(ref foundIndex[0], -1, (int)candidateIdx)
```

ILGPU's argument order is `target, compare, value`. This differs from
`System.Threading.Interlocked.CompareExchange`, whose order is
`target, value, compare`.

## Detection Is More Than Device Discovery

`GpuCracker.DetectAvailableGpus()` tries CUDA first, then OpenCL. It also calls
`ProbeKernelCompilation(...)` for each backend.

This matters because a system can see the GPU and still fail to compile this
specific kernel. The app reports a GPU as usable only when the crack kernel
compiles.
