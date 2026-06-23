# CardHashDemo

Educational .NET console demo that shows why fast hashes such as SHA1 and
SHA256 are unsafe for protecting credit card numbers.

The demo generates a valid test card number, hashes it, then brute-forces the
hash live using either CPU threads or a GPU kernel. It is intended for learning,
training, and authorized security testing only.

## What This Demonstrates

- A credit card PAN has much less entropy than it appears to have.
- The BIN is often known or easy to infer.
- The Luhn check digit is deterministic and does not add security.
- SHA1 and SHA256 are fast by design, so they are poor choices for small,
  structured secrets.
- Static and per-card salts stop rainbow-table reuse, but they do not stop a
  targeted brute-force attack when the attacker has the salt.

Correct storage patterns for real card data are tokenization or encryption with
proper key management. If hashing is unavoidable for a non-reversible use case,
use a slow password/KDF-style algorithm such as Argon2id or bcrypt with a real
work factor.

## Solution Layout

```text
CardHashDemo/
  CardHashDemo.slnx
  CardHashDemo.Core/
    Shared domain logic, demo text, Luhn, BIN list, CPU cracker, summaries.
  CardHashDemo.Cpu/
    Console app that runs the full demo using CPU parallelism.
  CardHashDemo.Gpu/
    Console app that runs the same demo using ILGPU on CUDA/OpenCL.
  CardHashDemo.Tests/
    Unit and GPU smoke tests.
  docs/
    Extra design notes, GPU architecture documentation, and draw.io diagrams.
```

## Projects

### CardHashDemo.Core

Shared library used by both console apps.

Important files:

- `LuhnAlgorithm.cs` validates cards and computes the check digit.
- `IsraeliCards.cs` stores known BIN entries and generates valid cards.
- `HashCracker.cs` performs the CPU brute-force attack.
- `GpuHash.cs` contains GPU-safe SHA1/SHA256 helpers.
- `DemoSections.cs` prints the educational explanation sections.
- `ResultSummary.cs` writes `summary-cpu.txt` or `summary-gpu.txt`.

### CardHashDemo.Cpu

Runs the demo without GPU dependencies. It uses `Parallel.For` and normal
.NET cryptography APIs to brute-force candidates on CPU cores.

Run:

```powershell
dotnet run --project CardHashDemo.Cpu\CardHashDemo.Cpu.csproj
```

### CardHashDemo.Gpu

Runs the demo with ILGPU. It detects usable CUDA/OpenCL backends, shows them as
numbered terminal options, and uses the backend you choose. Detection also
compiles the actual crack kernel, so a listed GPU means the demo kernel is
usable, not merely that Windows can see a GPU.

Run:

```powershell
dotnet run --project CardHashDemo.Gpu\CardHashDemo.Gpu.csproj
```

GPU notes:

- NVIDIA CUDA is the preferred backend.
- If CUDA and OpenCL are both usable, the GPU app asks you to choose `1`, `2`,
  and so on in the terminal.
- The kernel is optimized for 16-digit Visa/Mastercard-style cards.
- Supported salt lengths in the GPU kernel are `0` and `16` bytes.
- See `docs/gpu-architecture.md` for the detailed explanation.
- See `docs/cardhashdemo-architecture.drawio` for the visual architecture.

## Does the GPU Code Run Under .NET?

The project is a .NET project, and the GPU console app starts as a normal .NET
process. `Program.cs`, `GpuCracker.Crack(...)`, buffer allocation, progress
reporting, and result handling all run under the .NET runtime.

The important exception is the hot GPU method:

```csharp
private static void CrackKernel(...)
```

That method is written in C#, but ILGPU compiles it into GPU-native code for
CUDA or OpenCL. The compiled kernel is then executed by the GPU driver on the
GPU hardware. It is not executed by the normal .NET runtime.

That split is why the CPU code can be high-level C#, while the GPU kernel looks
low-level:

- CPU code can use strings, arrays, `Span<T>`, `SHA256.HashData`, exceptions,
  and normal .NET APIs.
- GPU kernel code must avoid managed allocations, strings, LINQ, exceptions,
  framework cryptography APIs, and non-blittable parameters.

In short:

```text
.NET app controls the demo and launches work
ILGPU compiles CrackKernel
CUDA/OpenCL executes the compiled kernel on the GPU
```

### CardHashDemo.Tests

Runs correctness checks for Luhn, card generation, CPU cracking, GPU-safe hash
functions, and GPU cracking when a supported GPU is available.

Run:

```powershell
dotnet test CardHashDemo.Tests\CardHashDemo.Tests.csproj
```

## Demo Flow

Both CPU and GPU apps follow the same story:

1. Explain SHA1/SHA256 and why speed is the problem.
2. Explain the Luhn algorithm and why it is not security.
3. Show known Israeli BIN prefixes.
4. Generate a valid target card number.
5. Store only hashes, then "forget" the original card.
6. Crack `SHA1(PAN)`, `SHA256(PAN)`, static-salt SHA256, and per-card-salt SHA256.
7. Compare timings and estimated Track 2 cracking times.
8. Write a summary file for CPU/GPU comparison.

## Requirements

General:

- Windows
- .NET 10 SDK

GPU mode:

- NVIDIA CUDA-capable GPU for best results
- Working NVIDIA driver/CUDA runtime
- Optional but useful for diagnostics: CUDA Toolkit and `nvidia-smi`

The CPU app should run on any machine with the .NET SDK installed.

## Output Files

Running the apps can create:

- `summary-cpu.txt`
- `summary-gpu.txt`

These files are generated reports from demo runs. They are useful for comparing
CPU and GPU performance on different machines.

## Troubleshooting

### GPU is visible but the demo says no GPU is usable

The app does more than detect a display adapter. It also compiles the ILGPU
crack kernel. If kernel compilation fails, the backend is treated as unusable.

Check:

```powershell
nvidia-smi
dotnet test CardHashDemo.Tests\CardHashDemo.Tests.csproj
```

### Kernel compilation errors

ILGPU kernels are restricted. Kernel parameters and local values must be simple
GPU-compatible values. For example, the code uses `int` flags instead of `bool`
kernel parameters because ILGPU 1.5.3 rejects `System.Boolean` kernel
parameters.

### Salted GPU attacks fail

The GPU kernel supports salt length `0` or `16` only. The demo keeps static and
per-card salts at exactly 16 bytes so the kernel can build one fixed SHA block
without dynamic allocation.

## Safety Scope

This repository is for education and authorized security testing. Do not use it
against real card data or systems without explicit permission.

## License

MIT License. See `LICENSE`.
