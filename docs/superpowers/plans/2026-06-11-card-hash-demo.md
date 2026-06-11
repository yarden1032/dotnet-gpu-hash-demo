# CardHashDemo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two C# console apps (CPU and GPU) that educationally demonstrate SHA1, SHA256, and SHA256-with-salt hash vulnerabilities for credit card PANs and Track 2 data, including a live brute-force crack with timing output.

**Architecture:** Three-project .NET 10 solution (`CardHashDemo.Core` class library shared by `CardHashDemo.Cpu` console app and `CardHashDemo.Gpu` console app). Core contains all domain logic; GPU app adds ILGPU CUDA kernels on top of the same demo flow. A `CardHashDemo.Tests` xUnit project covers Core logic.

**Tech Stack:** .NET 10, xUnit 2.x, ILGPU 1.5.x + ILGPU.Runtime.Cuda

---

## File Map

```
CardHashDemo/
├── CardHashDemo.sln
├── CardHashDemo.Core/
│   ├── CardHashDemo.Core.csproj
│   ├── ConsoleHelper.cs           — colored banners, table printing, pause prompts
│   ├── LuhnAlgorithm.cs           — Validate(span) and ComputeCheckDigit(span)
│   ├── IsraeliCards.cs            — BinEntry record, KnownBins list, GenerateCard
│   ├── HashCracker.cs             — Parallel.For engine, SaltMode enum, CrackResult record
│   └── DemoSections.cs            — SHA1Explainer, LuhnSection, BinSection, Track2Section, Takeaways
├── CardHashDemo.Tests/
│   ├── CardHashDemo.Tests.csproj
│   ├── LuhnAlgorithmTests.cs
│   ├── IsraeliCardsTests.cs
│   └── HashCrackerTests.cs
├── CardHashDemo.Cpu/
│   ├── CardHashDemo.Cpu.csproj
│   └── Program.cs                 — orchestrates full demo using Core + HashCracker
└── CardHashDemo.Gpu/
    ├── CardHashDemo.Gpu.csproj    — adds ILGPU + ILGPU.Runtime.Cuda
    ├── GpuHash.cs                 — W16 struct, Sha1Block, Sha256Block (ILGPU-safe)
    ├── GpuCracker.cs              — ILGPU kernel + CudaAccelerator setup
    └── Program.cs                 — same demo flow as Cpu, but cracking via GPU
```

---

## Task 1: Scaffold the solution

**Files:**
- Create: `CardHashDemo.sln`
- Create: `CardHashDemo.Core/CardHashDemo.Core.csproj`
- Create: `CardHashDemo.Tests/CardHashDemo.Tests.csproj`
- Create: `CardHashDemo.Cpu/CardHashDemo.Cpu.csproj`
- Create: `CardHashDemo.Gpu/CardHashDemo.Gpu.csproj`
- Create: `.gitignore`

- [ ] **Step 1: Create solution and projects**

```powershell
Set-Location C:\git\CardHashDemo
dotnet new sln -n CardHashDemo
dotnet new classlib -n CardHashDemo.Core -o CardHashDemo.Core --framework net10.0
dotnet new xunit   -n CardHashDemo.Tests -o CardHashDemo.Tests --framework net10.0
dotnet new console -n CardHashDemo.Cpu   -o CardHashDemo.Cpu   --framework net10.0
dotnet new console -n CardHashDemo.Gpu   -o CardHashDemo.Gpu   --framework net10.0
dotnet sln add CardHashDemo.Core/CardHashDemo.Core.csproj
dotnet sln add CardHashDemo.Tests/CardHashDemo.Tests.csproj
dotnet sln add CardHashDemo.Cpu/CardHashDemo.Cpu.csproj
dotnet sln add CardHashDemo.Gpu/CardHashDemo.Gpu.csproj
```

- [ ] **Step 2: Add project references**

```powershell
Set-Location C:\git\CardHashDemo
dotnet add CardHashDemo.Tests/CardHashDemo.Tests.csproj reference CardHashDemo.Core/CardHashDemo.Core.csproj
dotnet add CardHashDemo.Cpu/CardHashDemo.Cpu.csproj     reference CardHashDemo.Core/CardHashDemo.Core.csproj
dotnet add CardHashDemo.Gpu/CardHashDemo.Gpu.csproj     reference CardHashDemo.Core/CardHashDemo.Core.csproj
dotnet add CardHashDemo.Gpu/CardHashDemo.Gpu.csproj     package   ILGPU
dotnet add CardHashDemo.Gpu/CardHashDemo.Gpu.csproj     package   ILGPU.Runtime.Cuda
```

- [ ] **Step 3: Delete auto-generated placeholder files**

```powershell
Remove-Item CardHashDemo.Core\Class1.cs
Remove-Item CardHashDemo.Tests\UnitTest1.cs
```

- [ ] **Step 4: Add .gitignore**

Create `C:\git\CardHashDemo\.gitignore`:
```
bin/
obj/
*.user
.vs/
```

- [ ] **Step 5: Verify build**

```powershell
Set-Location C:\git\CardHashDemo
dotnet build
```
Expected: `Build succeeded.`

- [ ] **Step 6: Commit**

```powershell
Set-Location C:\git\CardHashDemo
git add .
git commit -m "feat: scaffold 4-project solution"
```

---

## Task 2: ConsoleHelper.cs

**Files:**
- Create: `CardHashDemo.Core/ConsoleHelper.cs`

- [ ] **Step 1: Write ConsoleHelper**

`CardHashDemo.Core/ConsoleHelper.cs`:
```csharp
namespace CardHashDemo.Core;

public static class ConsoleHelper
{
    public static void PrintHeader(string text)
    {
        string line = new('═', text.Length + 4);
        WriteColor(ConsoleColor.Cyan, $"╔{line}╗\n║  {text}  ║\n╚{line}╝");
        Console.WriteLine();
    }

    public static void PrintSection(string title)
    {
        Console.WriteLine();
        WriteColor(ConsoleColor.Yellow, $"▶ {title}");
        WriteColor(ConsoleColor.DarkGray, new string('─', title.Length + 2));
        Console.WriteLine();
    }

    public static void PrintInfo(string text)      => Console.WriteLine($"  {text}");
    public static void PrintSuccess(string text)   => WriteColor(ConsoleColor.Green,  $"  ✓ {text}");
    public static void PrintWarning(string text)   => WriteColor(ConsoleColor.Red,    $"  ⚠ {text}");
    public static void PrintHighlight(string label, string value)
    {
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write($"  {label}: ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(value);
        Console.ResetColor();
    }

    public static void PrintResultRow(string label, string value)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"[RESULT] {label,-28}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(value);
        Console.ResetColor();
    }

    public static void PrintComparisonTable(IEnumerable<(string Algorithm, TimeSpan Elapsed, double MHashSec)> rows)
    {
        Console.WriteLine();
        WriteColor(ConsoleColor.Yellow, "  " + new string('─', 68));
        WriteColor(ConsoleColor.Yellow, $"  {"Algorithm",-30} │ {"Elapsed",13} │ {"Speed",12}");
        WriteColor(ConsoleColor.Yellow, "  " + new string('─', 68));
        foreach (var (alg, elapsed, speed) in rows)
            WriteColor(ConsoleColor.White, $"  {alg,-30} │ {elapsed,13:hh\\:mm\\:ss\\.fff} │ {speed,9:F1} M/sec");
        WriteColor(ConsoleColor.Yellow, "  " + new string('─', 68));
        Console.WriteLine();
        WriteColor(ConsoleColor.Red, "  Salt defeats rainbow tables. It does NOT defeat brute force.");
        WriteColor(ConsoleColor.Red, "  The fix: use Argon2id or bcrypt with an appropriate work factor.");
        Console.WriteLine();
    }

    public static void PrintProgress(long tried, long total, TimeSpan elapsed, double mHashSec)
    {
        double pct = total > 0 ? tried * 100.0 / total : 0;
        Console.Write($"\r  [{pct,6:F2}%] {tried,13:N0} / {total:N0}  {mHashSec,6:F1} M/sec  {elapsed:hh\\:mm\\:ss\\.ff}   ");
    }

    public static void Pause(string message = "Press any key to continue...")
    {
        Console.WriteLine();
        WriteColor(ConsoleColor.DarkGray, $"  [{message}]");
        Console.ReadKey(true);
        Console.WriteLine();
    }

    private static void WriteColor(ConsoleColor color, string text)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }
}
```

- [ ] **Step 2: Build**

```powershell
dotnet build CardHashDemo.Core
```
Expected: `Build succeeded.`

- [ ] **Step 3: Commit**

```powershell
git add CardHashDemo.Core/ConsoleHelper.cs
git commit -m "feat(core): add ConsoleHelper with colored output and table printing"
```

---

## Task 3: LuhnAlgorithm — tests first

**Files:**
- Create: `CardHashDemo.Tests/LuhnAlgorithmTests.cs`

- [ ] **Step 1: Write failing tests**

`CardHashDemo.Tests/LuhnAlgorithmTests.cs`:
```csharp
using System.Text;
using CardHashDemo.Core;
using Xunit;

namespace CardHashDemo.Tests;

public class LuhnAlgorithmTests
{
    // Known valid cards
    [Theory]
    [InlineData("4111111111111111", true)]   // standard Visa test card
    [InlineData("4362010000000003", true)]   // Israeli Hapoalim BIN, free digits=000000000
    [InlineData("4362010000000004", false)]  // one digit off
    [InlineData("1234567890123452", true)]   // generic valid Luhn
    [InlineData("1234567890123451", false)]  // invalid
    public void Validate_KnownCards(string pan, bool expected)
    {
        bool result = LuhnAlgorithm.Validate(pan.AsSpan());
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ComputeCheckDigit_Hapoalim_IndexZero()
    {
        // Partial "436201000000000" (15 digits) → check digit must be 3
        byte[] partial = Encoding.ASCII.GetBytes("436201000000000");
        int checkDigit = LuhnAlgorithm.ComputeCheckDigit(partial);
        Assert.Equal(3, checkDigit);
    }

    [Fact]
    public void ComputeCheckDigit_VisaTest_IndexZero()
    {
        // Partial "411111111111111" → check digit must be 1
        byte[] partial = Encoding.ASCII.GetBytes("411111111111111");
        int checkDigit = LuhnAlgorithm.ComputeCheckDigit(partial);
        Assert.Equal(1, checkDigit);
    }

    [Fact]
    public void RoundTrip_GeneratedCard_AlwaysValid()
    {
        // Generate check digit and verify the full number validates
        byte[] partial = Encoding.ASCII.GetBytes("527136123456789");
        int cd = LuhnAlgorithm.ComputeCheckDigit(partial);
        string full = "527136123456789" + cd;
        Assert.True(LuhnAlgorithm.Validate(full.AsSpan()));
    }
}
```

- [ ] **Step 2: Run — expect failure (type not yet defined)**

```powershell
dotnet test CardHashDemo.Tests
```
Expected: compile error `The type or namespace name 'LuhnAlgorithm' does not exist`

---

## Task 4: LuhnAlgorithm — implementation

**Files:**
- Create: `CardHashDemo.Core/LuhnAlgorithm.cs`

- [ ] **Step 1: Implement LuhnAlgorithm**

`CardHashDemo.Core/LuhnAlgorithm.cs`:
```csharp
namespace CardHashDemo.Core;

public static class LuhnAlgorithm
{
    /// <summary>Validates a complete card number (including check digit) as a char span.</summary>
    public static bool Validate(ReadOnlySpan<char> pan)
    {
        if (pan.Length < 2) return false;
        int sum = 0;
        bool doubleIt = false; // rightmost digit (check digit, position 0) is NOT doubled
        for (int i = pan.Length - 1; i >= 0; i--)
        {
            int d = pan[i] - '0';
            if ((uint)d > 9) return false;
            if (doubleIt) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    /// <summary>
    /// Computes the Luhn check digit for a partial card number supplied as ASCII bytes.
    /// partialBytes must NOT include the check digit position.
    /// </summary>
    public static int ComputeCheckDigit(ReadOnlySpan<byte> partialBytes)
    {
        // Working from the rightmost partial digit, double every other digit starting
        // from the first (rightmost). That digit will be immediately left of the check digit.
        int sum = 0;
        bool doubleIt = true; // rightmost partial digit IS doubled (it becomes position 1 once check digit appended)
        for (int i = partialBytes.Length - 1; i >= 0; i--)
        {
            int d = partialBytes[i] - '0';
            if (doubleIt) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            doubleIt = !doubleIt;
        }
        return (10 - sum % 10) % 10;
    }
}
```

- [ ] **Step 2: Run tests — expect all pass**

```powershell
dotnet test CardHashDemo.Tests --filter "LuhnAlgorithm"
```
Expected:
```
Passed!  - Failed: 0, Passed: 7, Skipped: 0
```

- [ ] **Step 3: Commit**

```powershell
git add CardHashDemo.Core/LuhnAlgorithm.cs CardHashDemo.Tests/LuhnAlgorithmTests.cs
git commit -m "feat(core): implement LuhnAlgorithm with TDD"
```

---

## Task 5: IsraeliCards — tests first

**Files:**
- Create: `CardHashDemo.Tests/IsraeliCardsTests.cs`

- [ ] **Step 1: Write failing tests**

`CardHashDemo.Tests/IsraeliCardsTests.cs`:
```csharp
using CardHashDemo.Core;
using Xunit;

namespace CardHashDemo.Tests;

public class IsraeliCardsTests
{
    [Fact]
    public void KnownBins_HasAtLeast10Entries()
    {
        Assert.True(IsraeliCards.KnownBins.Count >= 10);
    }

    [Theory]
    [InlineData("4362010000000003", true)]  // Hapoalim prefix 436201
    [InlineData("5271360000000000", true)]  // Max prefix 527136
    [InlineData("4111111111111111", false)] // Not an Israeli BIN
    public void DetectIsraeli_KnownCards(string pan, bool expected)
    {
        var entry = IsraeliCards.DetectIsraeli(pan);
        Assert.Equal(expected, entry is not null);
    }

    [Fact]
    public void GenerateCard_ProducesValidLuhnCard()
    {
        var bin = IsraeliCards.KnownBins[0];
        string card = IsraeliCards.GenerateCard(bin);
        Assert.Equal(bin.CardLength, card.Length);
        Assert.StartsWith(bin.Prefix, card);
        Assert.True(LuhnAlgorithm.Validate(card.AsSpan()));
    }

    [Fact]
    public void GenerateCard_DifferentCallsProduceDifferentCards()
    {
        var bin = IsraeliCards.KnownBins[0];
        var cards = Enumerable.Range(0, 10).Select(_ => IsraeliCards.GenerateCard(bin)).ToHashSet();
        Assert.True(cards.Count > 1); // not all the same
    }
}
```

- [ ] **Step 2: Run — expect compile error**

```powershell
dotnet test CardHashDemo.Tests --filter "IsraeliCards"
```
Expected: compile error `The type or namespace name 'IsraeliCards' does not exist`

---

## Task 6: IsraeliCards — implementation

**Files:**
- Create: `CardHashDemo.Core/IsraeliCards.cs`

- [ ] **Step 1: Implement IsraeliCards**

`CardHashDemo.Core/IsraeliCards.cs`:
```csharp
using System.Text;

namespace CardHashDemo.Core;

public record BinEntry(string Prefix, string Issuer, int CardLength = 16);

public static class IsraeliCards
{
    public static readonly IReadOnlyList<BinEntry> KnownBins = new BinEntry[]
    {
        // Bank Hapoalim
        new("436201", "Bank Hapoalim Visa"),
        new("464100", "Bank Hapoalim Visa Platinum"),
        new("470640", "Bank Hapoalim Visa Gold"),
        // Bank Leumi
        new("492840", "Bank Leumi Visa"),
        new("431195", "Bank Leumi Visa Classic"),
        // Discount Bank
        new("479614", "Discount Bank Visa"),
        new("457946", "Discount Bank Visa Gold"),
        // Mizrahi-Tefahot
        new("454030", "Mizrahi-Tefahot Visa"),
        // Max (formerly Leumi Card / CAL)
        new("527136", "Max (Leumi Card) Mastercard"),
        new("526568", "Max Mastercard"),
        new("535840", "Max Mastercard Platinum"),
        new("527141", "CAL Mastercard"),
        new("526586", "Isracard Mastercard"),
        // American Express Israel (15 digits)
        new("376818", "American Express Israel", 15),
        // Diners Club Israel (14 digits)
        new("304920", "Diners Club Israel", 14),
    };

    public static BinEntry? DetectIsraeli(string pan)
    {
        foreach (var entry in KnownBins)
            if (pan.StartsWith(entry.Prefix, StringComparison.Ordinal))
                return entry;
        return null;
    }

    /// <summary>Generates a random card number with a valid Luhn check digit for the given BIN.</summary>
    public static string GenerateCard(BinEntry bin)
    {
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        var sb = new StringBuilder(bin.CardLength);
        sb.Append(bin.Prefix);
        for (int i = 0; i < freeDigits; i++)
            sb.Append((char)('0' + Random.Shared.Next(10)));
        byte[] partial = Encoding.ASCII.GetBytes(sb.ToString());
        sb.Append((char)('0' + LuhnAlgorithm.ComputeCheckDigit(partial)));
        return sb.ToString();
    }
}
```

- [ ] **Step 2: Run tests — expect all pass**

```powershell
dotnet test CardHashDemo.Tests --filter "IsraeliCards"
```
Expected:
```
Passed!  - Failed: 0, Passed: 5, Skipped: 0
```

- [ ] **Step 3: Commit**

```powershell
git add CardHashDemo.Core/IsraeliCards.cs CardHashDemo.Tests/IsraeliCardsTests.cs
git commit -m "feat(core): implement IsraeliCards BIN database with TDD"
```

---

## Task 7: HashCracker — tests first

**Files:**
- Create: `CardHashDemo.Tests/HashCrackerTests.cs`

These tests use a card at iteration index 0 (`436201000000000` + Luhn=3 = `4362010000000003`) so they complete in milliseconds.

- [ ] **Step 1: Write failing tests**

`CardHashDemo.Tests/HashCrackerTests.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;
using Xunit;

namespace CardHashDemo.Tests;

public class HashCrackerTests
{
    private static readonly BinEntry HapoalimBin = new("436201", "Bank Hapoalim Visa");

    // "4362010000000003" — free digits 000000000 = index 0, found immediately
    private const string KnownCard = "4362010000000003";

    private static string Sha1Hex(string input)
    {
        var bytes = SHA1.HashData(Encoding.ASCII.GetBytes(input));
        return Convert.ToHexString(bytes);
    }

    private static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(input));
        return Convert.ToHexString(bytes);
    }

    [Fact]
    public async Task Crack_Sha1_NoSalt_FindsCardAtIndexZero()
    {
        string hash = Sha1Hex(KnownCard);
        var result = await HashCracker.CrackAsync(hash, HapoalimBin, HashAlgorithmName.SHA1,
            SaltMode.None, salt: null, progress: null, ct: default);
        Assert.Equal(KnownCard, result.Card);
        Assert.True(result.Tried <= 2);
    }

    [Fact]
    public async Task Crack_Sha256_NoSalt_FindsCardAtIndexZero()
    {
        string hash = Sha256Hex(KnownCard);
        var result = await HashCracker.CrackAsync(hash, HapoalimBin, HashAlgorithmName.SHA256,
            SaltMode.None, salt: null, progress: null, ct: default);
        Assert.Equal(KnownCard, result.Card);
    }

    [Fact]
    public async Task Crack_Sha256_StaticSalt_FindsCard()
    {
        byte[] salt = Encoding.UTF8.GetBytes("MySuperSecretPepper");
        byte[] input = [.. salt, .. Encoding.ASCII.GetBytes(KnownCard)];
        string hash = Convert.ToHexString(SHA256.HashData(input));
        var result = await HashCracker.CrackAsync(hash, HapoalimBin, HashAlgorithmName.SHA256,
            SaltMode.Static, salt, progress: null, ct: default);
        Assert.Equal(KnownCard, result.Card);
    }

    [Fact]
    public async Task Crack_Sha256_PerCardSalt_FindsCard()
    {
        byte[] salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]; // 16-byte random salt
        byte[] input = [.. salt, .. Encoding.ASCII.GetBytes(KnownCard)];
        string hash = Convert.ToHexString(SHA256.HashData(input));
        var result = await HashCracker.CrackAsync(hash, HapoalimBin, HashAlgorithmName.SHA256,
            SaltMode.PerCard, salt, progress: null, ct: default);
        Assert.Equal(KnownCard, result.Card);
    }

    [Fact]
    public async Task Crack_ReturnsNullCard_WhenNotFound()
    {
        // Use a hash that doesn't belong to any card in this BIN
        string hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 40 hex chars (SHA1 length)
        // Limit iterations to avoid a 30-second wait — use a tiny search by passing a BIN
        // with cardLength=7 so freeDigits=0 and total=1 (just 1 candidate)
        var tinyBin = new BinEntry("436201", "Test", CardLength: 7);
        var result = await HashCracker.CrackAsync(hash, tinyBin, HashAlgorithmName.SHA1,
            SaltMode.None, salt: null, progress: null, ct: default);
        Assert.Null(result.Card);
        Assert.Equal(1, result.Total); // only 1 combination tried
    }
}
```

- [ ] **Step 2: Run — expect compile error**

```powershell
dotnet test CardHashDemo.Tests --filter "HashCracker"
```
Expected: compile error about missing `HashCracker`, `SaltMode`, `CrackResult`

---

## Task 8: HashCracker — implementation

**Files:**
- Create: `CardHashDemo.Core/HashCracker.cs`

- [ ] **Step 1: Implement HashCracker**

`CardHashDemo.Core/HashCracker.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;

namespace CardHashDemo.Core;

public enum SaltMode { None, Static, PerCard }

public record CrackResult(string? Card, TimeSpan Elapsed, long Tried, long Total, double HashesPerSecond);

public record CrackProgress(long Tried, long Total, TimeSpan Elapsed, double MHashSec);

public static class HashCracker
{
    public static Task<CrackResult> CrackAsync(
        string targetHashHex,
        BinEntry bin,
        HashAlgorithmName algorithm,
        SaltMode saltMode,
        byte[]? salt,
        IProgress<CrackProgress>? progress,
        CancellationToken ct)
    {
        return Task.Run(() => RunCrack(targetHashHex, bin, algorithm, saltMode, salt ?? [], progress, ct), ct);
    }

    private static CrackResult RunCrack(
        string targetHashHex,
        BinEntry bin,
        HashAlgorithmName algorithm,
        SaltMode saltMode,
        byte[] salt,
        IProgress<CrackProgress>? progress,
        CancellationToken ct)
    {
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        long totalCombinations = 1;
        for (int i = 0; i < freeDigits; i++) totalCombinations *= 10;

        byte[] targetHash = Convert.FromHexString(targetHashHex);
        byte[] binBytes   = Encoding.ASCII.GetBytes(bin.Prefix);
        bool isSha256     = algorithm == HashAlgorithmName.SHA256;

        string? foundCard   = null;
        long    processed   = 0;
        var     sw          = System.Diagnostics.Stopwatch.StartNew();

        var opts = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken      = ct,
        };

        try
        {
            Parallel.For(0L, totalCombinations, opts, (i, state) =>
            {
                if (state.ShouldExitCurrentIteration) return;

                // Build ASCII card bytes in a fixed-size stack buffer (max 19 for 19-digit cards)
                Span<byte> cardBytes = stackalloc byte[bin.CardLength];

                // Copy BIN
                for (int j = 0; j < binBytes.Length; j++) cardBytes[j] = binBytes[j];

                // Fill free digits from iteration index
                long val = i;
                for (int j = bin.CardLength - 2; j >= binBytes.Length; j--)
                {
                    cardBytes[j] = (byte)('0' + val % 10);
                    val /= 10;
                }

                // Luhn check digit
                cardBytes[bin.CardLength - 1] = (byte)('0' + LuhnAlgorithm.ComputeCheckDigit(cardBytes[..^1]));

                // Build hash input = salt || card
                int inputLen = salt.Length + bin.CardLength;
                Span<byte> inputBytes = stackalloc byte[inputLen];
                salt.CopyTo(inputBytes);
                cardBytes.CopyTo(inputBytes[salt.Length..]);

                // Compute hash
                Span<byte> hashBytes = stackalloc byte[32]; // enough for SHA256
                int hashLen = isSha256
                    ? SHA256.HashData(inputBytes, hashBytes)
                    : SHA1.HashData(inputBytes, hashBytes);

                if (hashBytes[..hashLen].SequenceEqual(targetHash))
                {
                    foundCard = Encoding.ASCII.GetString(cardBytes);
                    state.Stop();
                }

                // Progress — report every 500K, using atomic add to avoid per-iteration locking
                long p = Interlocked.Add(ref processed, 1);
                if (p % 500_000 == 0 && progress is not null)
                {
                    double sec  = sw.Elapsed.TotalSeconds;
                    double mhps = sec > 0 ? p / sec / 1_000_000.0 : 0;
                    progress.Report(new CrackProgress(p, totalCombinations, sw.Elapsed, mhps));
                }
            });
        }
        catch (OperationCanceledException) { }

        sw.Stop();
        long tried    = Interlocked.Read(ref processed);
        double mhpsFinal = sw.Elapsed.TotalSeconds > 0 ? tried / sw.Elapsed.TotalSeconds / 1_000_000.0 : 0;
        return new CrackResult(foundCard, sw.Elapsed, tried, totalCombinations, mhpsFinal);
    }
}
```

- [ ] **Step 2: Run tests — expect all pass**

```powershell
dotnet test CardHashDemo.Tests --filter "HashCracker"
```
Expected:
```
Passed!  - Failed: 0, Passed: 5, Skipped: 0
```

- [ ] **Step 3: Run all tests**

```powershell
dotnet test CardHashDemo.Tests
```
Expected:
```
Passed!  - Failed: 0, Passed: 17, Skipped: 0
```

- [ ] **Step 4: Commit**

```powershell
git add CardHashDemo.Core/HashCracker.cs CardHashDemo.Tests/HashCrackerTests.cs
git commit -m "feat(core): implement HashCracker supporting SHA1, SHA256, static and per-card salt"
```

---

## Task 9: DemoSections — narrative content

**Files:**
- Create: `CardHashDemo.Core/DemoSections.cs`

- [ ] **Step 1: Implement DemoSections**

`CardHashDemo.Core/DemoSections.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;

namespace CardHashDemo.Core;

public static class DemoSections
{
    public static void PrintSha1Explainer()
    {
        ConsoleHelper.PrintSection("What is SHA1?");
        ConsoleHelper.PrintInfo("SHA1 (Secure Hash Algorithm 1) was designed by NSA and published by NIST in 1995.");
        ConsoleHelper.PrintInfo("It produces a 160-bit (40 hex char) digest from any input.");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Properties that make it FAST (by design):");
        ConsoleHelper.PrintInfo("  • Software: ~500 MB/sec single-threaded on modern CPUs");
        ConsoleHelper.PrintInfo("  • GPU (RTX 3080): ~20 BILLION hashes/sec for short inputs");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Why SHA1 is broken for card data:");
        ConsoleHelper.PrintInfo("  1. No salt — identical inputs always produce identical outputs");
        ConsoleHelper.PrintInfo("  2. Deterministic — attacker can precompute or brute-force");
        ConsoleHelper.PrintInfo("  3. SHAttered (2017) — chosen-prefix collision attack exists");
        ConsoleHelper.PrintInfo("  4. Small input space — card numbers have structural constraints");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintWarning("PCI-DSS v4.0 §3.5: Strong cryptography required. SHA1 alone does NOT qualify.");
    }

    public static void PrintLuhnSection()
    {
        ConsoleHelper.PrintSection("The Luhn Algorithm (ISO/IEC 7812)");
        ConsoleHelper.PrintInfo("Also called 'mod 10'. Purpose: detect transcription errors — NOT security.");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("How it works for a 16-digit card:");
        ConsoleHelper.PrintInfo("  • First 6 digits = BIN (Bank Identification Number) — identifies issuer");
        ConsoleHelper.PrintInfo("  • Digits 7-15   = unique account number (9 free digits)");
        ConsoleHelper.PrintInfo("  • Digit 16      = Luhn check digit — FULLY DETERMINED by digits 1-15");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Consequence for an attacker:");
        ConsoleHelper.PrintInfo("  Total 16-digit numbers:         10^16 = 10,000,000,000,000,000");
        ConsoleHelper.PrintInfo("  With known BIN (6 digits):      10^9  =         1,000,000,000");
        ConsoleHelper.PrintInfo("  Luhn check digit is free (not:  still 10^9 — Luhn just computes last digit)");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintHighlight("Search space reduction", "factor of 10,000,000x just from knowing the BIN");

        // Live Luhn demo
        Console.WriteLine();
        ConsoleHelper.PrintInfo("Live demo — validating test card 4111111111111111:");
        bool valid = LuhnAlgorithm.Validate("4111111111111111".AsSpan());
        if (valid) ConsoleHelper.PrintSuccess("4111111111111111 — VALID Luhn ✓");
        else       ConsoleHelper.PrintWarning("4111111111111111 — INVALID");

        ConsoleHelper.PrintInfo("Checking 4111111111111112 (check digit off by 1):");
        bool invalid = LuhnAlgorithm.Validate("4111111111111112".AsSpan());
        if (!invalid) ConsoleHelper.PrintSuccess("4111111111111112 — correctly rejected as INVALID ✓");
    }

    public static void PrintBinSection()
    {
        ConsoleHelper.PrintSection("Israeli Card BIN Prefixes");
        ConsoleHelper.PrintInfo("Knowing the card is Israeli constrains the first 6 digits to ~15 known values.");
        ConsoleHelper.PrintInfo("(Approximate — for educational use only)");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"  {"Prefix",-8} {"Issuer",-35} {"Length",6}");
        Console.WriteLine($"  {new string('─', 53)}");
        foreach (var b in IsraeliCards.KnownBins)
            Console.WriteLine($"  {b.Prefix,-8} {b.Issuer,-35} {b.CardLength,6}");
        Console.ResetColor();
        Console.WriteLine();
        ConsoleHelper.PrintHighlight("Total candidates per BIN (16-digit)", "1,000,000,000  (10^9)");
        ConsoleHelper.PrintHighlight("With ~15 Israeli BINs",               "~15,000,000,000 (15 × 10^9)");
    }

    public static void PrintTrack2Section()
    {
        ConsoleHelper.PrintSection("What about SHA1(Track 2)?");
        ConsoleHelper.PrintInfo("Track 2 format on the magnetic stripe:");
        ConsoleHelper.PrintHighlight("Format", ";PAN=YYMM SC DISC?");
        ConsoleHelper.PrintHighlight("Example", ";4362010000000003=2512101000000000?");
        Console.WriteLine();
        ConsoleHelper.PrintInfo("Expanded search space:");
        ConsoleHelper.PrintInfo("  PAN combinations (Israeli BIN):    10^9");
        ConsoleHelper.PrintInfo("  Expiry (12 months × 5-6 years):     ~72 values");
        ConsoleHelper.PrintInfo("  Service Code (common values):        ~15 values");
        ConsoleHelper.PrintInfo("  Discretionary data:                 often zeros or constant");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintHighlight("Total per BIN", "~10^9 × 72 × 15 ≈ 1.1 × 10^12");
        Console.WriteLine();
        ConsoleHelper.PrintInfo("CPU (8 cores, 24M hash/sec):  ~13 hours per BIN");
        ConsoleHelper.PrintInfo("GPU (RTX 3080, 20B hash/sec): ~55 seconds per BIN");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintWarning("With leaked expiry year → multiply above by 1/6 → GPU: ~9 seconds per BIN");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Conclusion: SHA1(Track2) is still breakable — only slower.");
    }

    public static void PrintTakeaways()
    {
        ConsoleHelper.PrintSection("Key Takeaways");
        ConsoleHelper.PrintWarning("NEVER hash card data with SHA1, SHA256, or any fast hash.");
        Console.WriteLine();
        ConsoleHelper.PrintInfo("The problem is SPEED, not algorithm strength:");
        ConsoleHelper.PrintInfo("  • SHA1 = ~500M/sec; SHA256 = ~250M/sec — both too fast");
        ConsoleHelper.PrintInfo("  • Salt defeats rainbow tables, NOT targeted brute force");
        ConsoleHelper.PrintInfo("  • Per-card random salt + SHA256: attacker has both hash and salt from the DB");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Correct approaches:");
        ConsoleHelper.PrintSuccess("Tokenization: store a random token mapped to the PAN in a PCI-scoped vault");
        ConsoleHelper.PrintSuccess("Encryption: AES-256 with a properly managed key — reversible by design");
        ConsoleHelper.PrintSuccess("If you MUST hash: use Argon2id / bcrypt with a work factor (slow by design)");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintHighlight("PCI-DSS v4.0 reference", "Requirement 3.5 — protecting stored account data");
    }
}
```

- [ ] **Step 2: Build**

```powershell
dotnet build CardHashDemo.Core
```
Expected: `Build succeeded.`

- [ ] **Step 3: Commit**

```powershell
git add CardHashDemo.Core/DemoSections.cs
git commit -m "feat(core): add DemoSections narrative content"
```

---

## Task 10: CPU Program.cs — full demo flow

**Files:**
- Modify: `CardHashDemo.Cpu/Program.cs`

- [ ] **Step 1: Write Program.cs**

`CardHashDemo.Cpu/Program.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;

Console.OutputEncoding = Encoding.UTF8;
Console.Clear();

ConsoleHelper.PrintHeader("SHA1 / SHA256 Credit Card Hash Vulnerability Demo  [CPU]");
ConsoleHelper.PrintWarning("EDUCATIONAL USE ONLY — authorized security testing / research");
ConsoleHelper.Pause();

// ── Section 1: SHA1 explainer ─────────────────────────────────────────────
DemoSections.PrintSha1Explainer();
ConsoleHelper.Pause();

// ── Section 2: Luhn algorithm ────────────────────────────────────────────
DemoSections.PrintLuhnSection();
ConsoleHelper.Pause();

// ── Section 3: Israeli BINs ──────────────────────────────────────────────
DemoSections.PrintBinSection();
ConsoleHelper.Pause();

// ── Generate target card ─────────────────────────────────────────────────
ConsoleHelper.PrintSection("Generating Target Card");
var bin = IsraeliCards.KnownBins[Random.Shared.Next(IsraeliCards.KnownBins.Count)];
// Limit to 16-digit cards for the live demo (Amex/Diners have different lengths)
while (bin.CardLength != 16)
    bin = IsraeliCards.KnownBins[Random.Shared.Next(IsraeliCards.KnownBins.Count)];

string card = IsraeliCards.GenerateCard(bin);
ConsoleHelper.PrintHighlight("Generated card (stored in payment system)", card);
ConsoleHelper.PrintHighlight("BIN", $"{bin.Prefix} — {bin.Issuer}");

byte[] cardAscii      = Encoding.ASCII.GetBytes(card);
// CPU app can use any salt length — HashCracker handles it via stackalloc
byte[] staticSalt     = Encoding.UTF8.GetBytes("MySuperSecretPepper"); // 19 bytes
byte[] perCardSalt    = new byte[16];
Random.Shared.NextBytes(perCardSalt);

string sha1Hash        = Convert.ToHexString(SHA1.HashData(cardAscii));
string sha256Hash      = Convert.ToHexString(SHA256.HashData(cardAscii));
string sha256Static    = Convert.ToHexString(SHA256.HashData([.. staticSalt, .. cardAscii]));
string sha256PerCard   = Convert.ToHexString(SHA256.HashData([.. perCardSalt, .. cardAscii]));

Console.WriteLine();
ConsoleHelper.PrintHighlight("SHA1(PAN)   stored in DB", sha1Hash);
ConsoleHelper.PrintHighlight("SHA256(PAN) stored in DB", sha256Hash);
ConsoleHelper.PrintHighlight("SHA256(static-salt+PAN)  ", sha256Static);
ConsoleHelper.PrintHighlight("SHA256(per-card-salt+PAN)", sha256PerCard);
ConsoleHelper.PrintHighlight("Per-card salt (also in DB)", Convert.ToHexString(perCardSalt));

Console.WriteLine();
ConsoleHelper.PrintInfo("Original card number is now 'forgotten'...");
ConsoleHelper.PrintInfo($"Attacker has: the hash + knows it is an Israeli {bin.CardLength}-digit card");
ConsoleHelper.Pause("Press any key to start cracking...");

// ── Progress reporter ─────────────────────────────────────────────────────
var progressReporter = new Progress<CrackProgress>(p =>
    ConsoleHelper.PrintProgress(p.Tried, p.Total, p.Elapsed, p.MHashSec));

var results = new List<(string Algorithm, TimeSpan Elapsed, double MHashSec)>();

// ── Crack 1: SHA1, no salt ────────────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 1 — SHA1 (no salt)");
ConsoleHelper.PrintInfo($"Iterating all {1_000_000_000:N0} combinations for BIN {bin.Prefix}...");
var r1 = await HashCracker.CrackAsync(sha1Hash, bin, HashAlgorithmName.SHA1,
    SaltMode.None, null, progressReporter, default);
Console.WriteLine();
PrintResult("SHA1 (no salt)", r1, card);
results.Add(("SHA1  (no salt)", r1.Elapsed, r1.HashesPerSecond));
ConsoleHelper.Pause();

// ── Crack 2: SHA256, no salt ──────────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 2 — SHA256 (no salt)");
ConsoleHelper.PrintInfo("Same attack, stronger algorithm. Still only ~2× slower.");
var r2 = await HashCracker.CrackAsync(sha256Hash, bin, HashAlgorithmName.SHA256,
    SaltMode.None, null, progressReporter, default);
Console.WriteLine();
PrintResult("SHA256 (no salt)", r2, card);
results.Add(("SHA256 (no salt)", r2.Elapsed, r2.HashesPerSecond));
ConsoleHelper.Pause();

// ── Crack 3: SHA256, static salt ──────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 3 — SHA256 with static salt");
ConsoleHelper.PrintInfo("Salt: \"MySuperSecretPepper\" (known from leaked source code)");
ConsoleHelper.PrintInfo("Attacker simply prepends the salt to every candidate. Same speed.");
var r3 = await HashCracker.CrackAsync(sha256Static, bin, HashAlgorithmName.SHA256,
    SaltMode.Static, staticSalt, progressReporter, default);
Console.WriteLine();
PrintResult("SHA256 (static salt)", r3, card);
results.Add(("SHA256 (static salt \"MySuperSecretPepper\")", r3.Elapsed, r3.HashesPerSecond));
ConsoleHelper.Pause();

// ── Crack 4: SHA256, per-card salt ────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 4 — SHA256 with per-card random salt");
ConsoleHelper.PrintInfo("Salt is random and unique per card. Stored alongside hash in the DB row.");
ConsoleHelper.PrintInfo("Attacker who stole the DB has both the hash AND the salt. Still full speed.");
var r4 = await HashCracker.CrackAsync(sha256PerCard, bin, HashAlgorithmName.SHA256,
    SaltMode.PerCard, perCardSalt, progressReporter, default);
Console.WriteLine();
PrintResult("SHA256 (per-card random salt)", r4, card);
results.Add(("SHA256 (per-card random salt, 16 bytes)", r4.Elapsed, r4.HashesPerSecond));
ConsoleHelper.Pause();

// ── Comparison table ──────────────────────────────────────────────────────
ConsoleHelper.PrintSection("Summary");
ConsoleHelper.PrintHighlight("Original card", card);
ConsoleHelper.PrintComparisonTable(results);

// ── Track2 section ────────────────────────────────────────────────────────
DemoSections.PrintTrack2Section();
ConsoleHelper.Pause();

// ── Takeaways ─────────────────────────────────────────────────────────────
DemoSections.PrintTakeaways();

static void PrintResult(string label, CrackResult r, string expectedCard)
{
    ConsoleHelper.PrintResultRow("Algorithm", label);
    if (r.Card is not null)
    {
        ConsoleHelper.PrintResultRow("Card found", r.Card);
        if (r.Card == expectedCard)
            ConsoleHelper.PrintSuccess("Recovered card matches the original!");
        else
            ConsoleHelper.PrintWarning("Mismatch — unexpected!");
    }
    else
    {
        ConsoleHelper.PrintWarning("Card not found (unexpected).");
    }
    ConsoleHelper.PrintResultRow("Elapsed",    r.Elapsed.ToString(@"hh\:mm\:ss\.fff"));
    ConsoleHelper.PrintResultRow("Speed",      $"{r.HashesPerSecond:F1} M hash/sec");
    ConsoleHelper.PrintResultRow("Combinations tried", $"{r.Tried:N0} / {r.Total:N0}");
}
```

- [ ] **Step 2: Build and run**

```powershell
dotnet build CardHashDemo.Cpu
dotnet run --project CardHashDemo.Cpu
```
Expected: demo runs to completion, prints found card and timing table.

- [ ] **Step 3: Commit**

```powershell
git add CardHashDemo.Cpu/Program.cs
git commit -m "feat(cpu): implement full demo flow in CPU console app"
```

---

## Task 11: GPU — kernel helpers (GpuHash.cs)

**Files:**
- Create: `CardHashDemo.Gpu/GpuHash.cs`

This file implements SHA1 and SHA256 as pure arithmetic C# methods that compile to ILGPU GPU kernels (no heap allocation, no virtual dispatch, value types only).

- [ ] **Step 1: Implement GpuHash.cs**

`CardHashDemo.Gpu/GpuHash.cs`:
```csharp
namespace CardHashDemo.Gpu;

/// <summary>
/// 16-element circular buffer for the SHA message schedule W[0..79].
/// Uses only value-type fields — safe for use inside ILGPU GPU kernels.
/// </summary>
internal struct W16
{
    private uint _0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15;

    internal void Set(int i, uint v)
    {
        switch (i & 15)
        {
            case  0: _0=v;  break; case  1: _1=v;  break; case  2: _2=v;  break; case  3: _3=v;  break;
            case  4: _4=v;  break; case  5: _5=v;  break; case  6: _6=v;  break; case  7: _7=v;  break;
            case  8: _8=v;  break; case  9: _9=v;  break; case 10: _10=v; break; case 11: _11=v; break;
            case 12: _12=v; break; case 13: _13=v; break; case 14: _14=v; break; default: _15=v; break;
        }
    }

    internal uint Get(int i) => (i & 15) switch
    {
        0=>_0, 1=>_1, 2=>_2, 3=>_3, 4=>_4, 5=>_5, 6=>_6, 7=>_7,
        8=>_8, 9=>_9, 10=>_10, 11=>_11, 12=>_12, 13=>_13, 14=>_14, _=>_15
    };

    internal void Expand(int round)
    {
        uint v = Get(round-3) ^ Get(round-8) ^ Get(round-14) ^ Get(round-16);
        Set(round, (v << 1) | (v >> 31)); // ROTL1
    }
}

/// <summary>SHA1 and SHA256 block functions safe for ILGPU GPU kernels.</summary>
internal static class GpuHash
{
    // ── SHA1 ─────────────────────────────────────────────────────────────

    private static void Sha1Block(ref W16 w,
        out uint h0, out uint h1, out uint h2, out uint h3, out uint h4)
    {
        const uint A0=0x67452301u, B0=0xEFCDAB89u, C0=0x98BADCFEu, D0=0x10325476u, E0=0xC3D2E1F0u;
        uint a=A0, b=B0, c=C0, d=D0, e=E0;
        for (int t = 0; t < 80; t++)
        {
            if (t >= 16) w.Expand(t);
            uint wt = w.Get(t);
            uint f, k;
            if      (t < 20) { f = (b&c)|(~b&d);          k = 0x5A827999u; }
            else if (t < 40) { f = b^c^d;                  k = 0x6ED9EBA1u; }
            else if (t < 60) { f = (b&c)|(b&d)|(c&d);     k = 0x8F1BBCDCu; }
            else             { f = b^c^d;                  k = 0xCA62C1D6u; }
            uint temp = ((a<<5)|(a>>27)) + f + e + k + wt;
            e=d; d=c; c=(b<<30)|(b>>2); b=a; a=temp;
        }
        h0=A0+a; h1=B0+b; h2=C0+c; h3=D0+d; h4=E0+e;
    }

    /// <summary>
    /// SHA1 of a single padded 512-bit block supplied as 16 big-endian 32-bit words.
    /// Call <see cref="BuildPaddedBlock"/> to prepare the block.
    /// </summary>
    internal static void Sha1(uint m0, uint m1, uint m2, uint m3,
                               uint m4, uint m5, uint m6, uint m7,
                               uint m8, uint m9, uint m10, uint m11,
                               uint m12, uint m13, uint m14, uint m15,
                               out uint h0, out uint h1, out uint h2, out uint h3, out uint h4)
    {
        var w = new W16();
        w.Set(0,m0); w.Set(1,m1); w.Set(2,m2);   w.Set(3,m3);
        w.Set(4,m4); w.Set(5,m5); w.Set(6,m6);   w.Set(7,m7);
        w.Set(8,m8); w.Set(9,m9); w.Set(10,m10); w.Set(11,m11);
        w.Set(12,m12); w.Set(13,m13); w.Set(14,m14); w.Set(15,m15);
        Sha1Block(ref w, out h0, out h1, out h2, out h3, out h4);
    }

    // ── SHA256 ────────────────────────────────────────────────────────────

    // Switch-based constant lookup — ILGPU cannot use static readonly arrays in GPU kernels.
    private static uint GetK256(int t) => t switch {
        0  => 0x428a2f98u, 1  => 0x71374491u, 2  => 0xb5c0fbcfu, 3  => 0xe9b5dba5u,
        4  => 0x3956c25bu, 5  => 0x59f111f1u, 6  => 0x923f82a4u, 7  => 0xab1c5ed5u,
        8  => 0xd807aa98u, 9  => 0x12835b01u, 10 => 0x243185beu, 11 => 0x550c7dc3u,
        12 => 0x72be5d74u, 13 => 0x80deb1feu, 14 => 0x9bdc06a7u, 15 => 0xc19bf174u,
        16 => 0xe49b69c1u, 17 => 0xefbe4786u, 18 => 0x0fc19dc6u, 19 => 0x240ca1ccu,
        20 => 0x2de92c6fu, 21 => 0x4a7484aau, 22 => 0x5cb0a9dcu, 23 => 0x76f988dau,
        24 => 0x983e5152u, 25 => 0xa831c66du, 26 => 0xb00327c8u, 27 => 0xbf597fc7u,
        28 => 0xc6e00bf3u, 29 => 0xd5a79147u, 30 => 0x06ca6351u, 31 => 0x14292967u,
        32 => 0x27b70a85u, 33 => 0x2e1b2138u, 34 => 0x4d2c6dfcu, 35 => 0x53380d13u,
        36 => 0x650a7354u, 37 => 0x766a0abbu, 38 => 0x81c2c92eu, 39 => 0x92722c85u,
        40 => 0xa2bfe8a1u, 41 => 0xa81a664bu, 42 => 0xc24b8b70u, 43 => 0xc76c51a3u,
        44 => 0xd192e819u, 45 => 0xd6990624u, 46 => 0xf40e3585u, 47 => 0x106aa070u,
        48 => 0x19a4c116u, 49 => 0x1e376c08u, 50 => 0x2748774cu, 51 => 0x34b0bcb5u,
        52 => 0x391c0cb3u, 53 => 0x4ed8aa4au, 54 => 0x5b9cca4fu, 55 => 0x682e6ff3u,
        56 => 0x748f82eeu, 57 => 0x78a5636fu, 58 => 0x84c87814u, 59 => 0x8cc70208u,
        60 => 0x90befffau, 61 => 0xa4506cebu, 62 => 0xbef9a3f7u, _ => 0xc67178f2u
    };

    private static void Sha256Block(ref W16 w,
        out uint h0, out uint h1, out uint h2, out uint h3,
        out uint h4, out uint h5, out uint h6, out uint h7)
    {
        const uint A0=0x6a09e667u, B0=0xbb67ae85u, C0=0x3c6ef372u, D0=0xa54ff53au;
        const uint E0=0x510e527fu, F0=0x9b05688cu, G0=0x1f83d9abu, H0val=0x5be0cd19u;
        uint a=A0,b=B0,c=C0,d=D0,e=E0,f=F0,g=G0,h=H0val;
        for (int t = 0; t < 64; t++)
        {
            if (t >= 16)
            {
                // W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
                uint wt2  = w.Get(t-2);
                uint wt7  = w.Get(t-7);
                uint wt15 = w.Get(t-15);
                uint wt16 = w.Get(t-16);
                uint s1 = ((wt2>>17)|(wt2<<15)) ^ ((wt2>>19)|(wt2<<13)) ^ (wt2>>10);
                uint s0 = ((wt15>>7)|(wt15<<25)) ^ ((wt15>>18)|(wt15<<14)) ^ (wt15>>3);
                w.Set(t, s1 + wt7 + s0 + wt16);
            }
            uint wt = w.Get(t);
            uint S1  = ((e>>6)|(e<<26)) ^ ((e>>11)|(e<<21)) ^ ((e>>25)|(e<<7));
            uint ch  = (e&f)^(~e&g);
            uint temp1 = h + S1 + ch + GetK256(t) + wt;
            uint S0  = ((a>>2)|(a<<30)) ^ ((a>>13)|(a<<19)) ^ ((a>>22)|(a<<10));
            uint maj = (a&b)^(a&c)^(b&c);
            uint temp2 = S0 + maj;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h0=A0+a; h1=B0+b; h2=C0+c; h3=D0+d; h4=E0+e; h5=F0+f; h6=G0+g; h7=H0val+h;
    }

    internal static void Sha256(uint m0, uint m1, uint m2, uint m3,
                                 uint m4, uint m5, uint m6, uint m7,
                                 uint m8, uint m9, uint m10, uint m11,
                                 uint m12, uint m13, uint m14, uint m15,
                                 out uint h0, out uint h1, out uint h2, out uint h3,
                                 out uint h4, out uint h5, out uint h6, out uint h7)
    {
        var w = new W16();
        w.Set(0,m0); w.Set(1,m1); w.Set(2,m2);   w.Set(3,m3);
        w.Set(4,m4); w.Set(5,m5); w.Set(6,m6);   w.Set(7,m7);
        w.Set(8,m8); w.Set(9,m9); w.Set(10,m10); w.Set(11,m11);
        w.Set(12,m12); w.Set(13,m13); w.Set(14,m14); w.Set(15,m15);
        Sha256Block(ref w, out h0, out h1, out h2, out h3, out h4, out h5, out h6, out h7);
    }

    // ── Shared helper ─────────────────────────────────────────────────────

    /// <summary>
    /// Packs inputBytes (length inputLen) into a single 512-bit (64-byte) padded SHA block.
    /// Requires inputLen ≤ 55 bytes so padding fits in one block.
    /// Words are returned as individual out parameters for use in kernel calls.
    /// </summary>
    internal static void BuildPaddedBlock(
        ReadOnlySpan<byte> inputBytes, int inputLen, bool isSha256,
        out uint m0,  out uint m1,  out uint m2,  out uint m3,
        out uint m4,  out uint m5,  out uint m6,  out uint m7,
        out uint m8,  out uint m9,  out uint m10, out uint m11,
        out uint m12, out uint m13, out uint m14, out uint m15)
    {
        Span<byte> block = stackalloc byte[64];
        block.Clear();
        inputBytes[..inputLen].CopyTo(block);
        block[inputLen] = 0x80;
        // Big-endian bit-length in last 8 bytes
        ulong bitLen = (ulong)inputLen * 8;
        block[56] = (byte)(bitLen >> 56); block[57] = (byte)(bitLen >> 48);
        block[58] = (byte)(bitLen >> 40); block[59] = (byte)(bitLen >> 32);
        block[60] = (byte)(bitLen >> 24); block[61] = (byte)(bitLen >> 16);
        block[62] = (byte)(bitLen >>  8); block[63] = (byte)(bitLen);

        static uint BE(ReadOnlySpan<byte> b, int i) =>
            ((uint)b[i]<<24)|((uint)b[i+1]<<16)|((uint)b[i+2]<<8)|(uint)b[i+3];

        m0=BE(block,0);  m1=BE(block,4);  m2=BE(block,8);  m3=BE(block,12);
        m4=BE(block,16); m5=BE(block,20); m6=BE(block,24); m7=BE(block,28);
        m8=BE(block,32); m9=BE(block,36); m10=BE(block,40); m11=BE(block,44);
        m12=BE(block,48); m13=BE(block,52); m14=BE(block,56); m15=BE(block,60);
    }
}
```

- [ ] **Step 2: Add a quick CPU-side unit test for the GPU hash functions**

Add to `CardHashDemo.Tests/HashCrackerTests.cs` (append to bottom of file):
```csharp
// Verify GpuHash produces same output as .NET SHA1/SHA256 for a known input
[Fact]
public void GpuHash_Sha1_MatchesDotNet()
{
    // SHA1("4362010000000003") — .NET reference
    byte[] input = Encoding.ASCII.GetBytes("4362010000000003");
    byte[] expected = SHA1.HashData(input);

    // Build padded block
    GpuHash.BuildPaddedBlock(input, 16, false,
        out var m0, out var m1, out var m2, out var m3,
        out var m4, out var m5, out var m6, out var m7,
        out var m8, out var m9, out var m10, out var m11,
        out var m12, out var m13, out var m14, out var m15);

    GpuHash.Sha1(m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,
        out var h0, out var h1, out var h2, out var h3, out var h4);

    Span<byte> actual = stackalloc byte[20];
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual,      h0);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[4..], h1);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[8..], h2);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[12..],h3);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[16..],h4);

    Assert.Equal(expected, actual.ToArray());
}

[Fact]
public void GpuHash_Sha256_MatchesDotNet()
{
    byte[] input = Encoding.ASCII.GetBytes("4362010000000003");
    byte[] expected = SHA256.HashData(input);

    GpuHash.BuildPaddedBlock(input, 16, true,
        out var m0, out var m1, out var m2, out var m3,
        out var m4, out var m5, out var m6, out var m7,
        out var m8, out var m9, out var m10, out var m11,
        out var m12, out var m13, out var m14, out var m15);

    GpuHash.Sha256(m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,
        out var h0, out var h1, out var h2, out var h3,
        out var h4, out var h5, out var h6, out var h7);

    Span<byte> actual = stackalloc byte[32];
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual,      h0);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[4..], h1);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[8..], h2);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[12..],h3);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[16..],h4);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[20..],h5);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[24..],h6);
    System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(actual[28..],h7);

    Assert.Equal(expected, actual.ToArray());
}
```

Note: `GpuHash` is in `CardHashDemo.Gpu` project; add a reference from Tests to Gpu for these tests, or move `GpuHash.cs` into Core (preferred — see note below).

> **Implementation note:** To avoid referencing the GPU project from Tests (which would force ILGPU on the test runner), move `GpuHash.cs` to `CardHashDemo.Core`. It has no ILGPU dependency — it is pure C# arithmetic. The GPU project accesses it via the Core reference it already has.

Move the file:
```powershell
Move-Item CardHashDemo.Gpu\GpuHash.cs CardHashDemo.Core\GpuHash.cs
# Update namespace in file from CardHashDemo.Gpu to CardHashDemo.Core
```

- [ ] **Step 3: Run tests — expect all pass**

```powershell
dotnet test CardHashDemo.Tests
```
Expected: all pass including the two new GpuHash tests.

- [ ] **Step 4: Commit**

```powershell
git add CardHashDemo.Core/GpuHash.cs CardHashDemo.Tests/HashCrackerTests.cs
git commit -m "feat(core): add GpuHash SHA1/SHA256 pure-arithmetic implementation with tests"
```

---

## Task 12: GPU — cracker kernel (GpuCracker.cs)

**Files:**
- Create: `CardHashDemo.Gpu/GpuCracker.cs`

- [ ] **Step 1: Implement GpuCracker.cs**

`CardHashDemo.Gpu/GpuCracker.cs`:
```csharp
using System.Text;
using CardHashDemo.Core;
using ILGPU;
using ILGPU.Runtime;
using ILGPU.Runtime.Cuda;

namespace CardHashDemo.Gpu;

public record GpuCrackResult(string? Card, TimeSpan Elapsed, long Tried, long Total, double GHashSec);

public static class GpuCracker
{
    private const int BatchSize = 1 << 24; // 16M candidates per GPU launch

    public static GpuCrackResult Crack(
        string targetHashHex,
        BinEntry bin,
        bool useSha256,
        byte[] salt,
        IProgress<(long tried, long total, TimeSpan elapsed)>? progress = null)
    {
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        long total = 1;
        for (int i = 0; i < freeDigits; i++) total *= 10;

        byte[] targetHash = Convert.FromHexString(targetHashHex);
        byte[] binBytes   = Encoding.ASCII.GetBytes(bin.Prefix);
        int    hashLen    = useSha256 ? 32 : 20;

        using var context     = Context.CreateDefault();
        using var accelerator = context.CreateCudaAccelerator(0);

        using var dBin        = accelerator.Allocate1D(binBytes);
        using var dTarget     = accelerator.Allocate1D(targetHash);
        using var dSalt       = accelerator.Allocate1D(salt.Length > 0 ? salt : new byte[1]);
        using var dFound      = accelerator.Allocate1D<long>(1);
        using var dFoundCard  = accelerator.Allocate1D<byte>(bin.CardLength);

        // -1 sentinel = not found
        dFound.CopyFromCPU([-1L]);

        var kernel = accelerator.LoadAutoGroupedStreamKernel<
            Index1D,
            long,          // batchOffset
            long,          // total
            ArrayView1D<byte, Stride1D.Dense>,   // bin
            int,           // binLen
            int,           // cardLength
            int,           // freeDigits
            ArrayView1D<byte, Stride1D.Dense>,   // targetHash
            int,           // hashLen
            bool,          // useSha256
            int,           // saltLength
            ArrayView1D<byte, Stride1D.Dense>,   // salt
            ArrayView1D<long, Stride1D.Dense>,   // foundIndex
            ArrayView1D<byte, Stride1D.Dense>    // foundCard
        >(CrackKernel);

        var sw   = System.Diagnostics.Stopwatch.StartNew();
        long tried = 0;
        string? foundCard = null;

        for (long offset = 0; offset < total; offset += BatchSize)
        {
            long batchLen = Math.Min(BatchSize, total - offset);
            kernel((int)batchLen, offset, total,
                dBin.View, bin.Prefix.Length, bin.CardLength, freeDigits,
                dTarget.View, hashLen, useSha256,
                salt.Length, dSalt.View,
                dFound.View, dFoundCard.View);
            accelerator.Synchronize();
            tried += batchLen;

            // Check if found
            long[] foundBuf = new long[1];
            dFound.CopyToCPU(foundBuf);
            if (foundBuf[0] >= 0)
            {
                byte[] cardBuf = new byte[bin.CardLength];
                dFoundCard.CopyToCPU(cardBuf);
                foundCard = Encoding.ASCII.GetString(cardBuf);
                break;
            }

            progress?.Report((tried, total, sw.Elapsed));
        }

        sw.Stop();
        double ghps = sw.Elapsed.TotalSeconds > 0 ? tried / sw.Elapsed.TotalSeconds / 1_000_000_000.0 : 0;
        return new GpuCrackResult(foundCard, sw.Elapsed, tried, total, ghps);
    }

    private static void CrackKernel(
        Index1D index,
        long batchOffset,
        long totalCombinations,
        ArrayView1D<byte, Stride1D.Dense> bin,
        int binLen,
        int cardLength,
        int freeDigits,
        ArrayView1D<byte, Stride1D.Dense> targetHash,
        int hashLen,
        bool useSha256,
        int saltLength,
        ArrayView1D<byte, Stride1D.Dense> salt,
        ArrayView1D<long, Stride1D.Dense> foundIndex,
        ArrayView1D<byte, Stride1D.Dense> foundCard)
    {
        long candidateIdx = batchOffset + index.X;
        if (candidateIdx >= totalCombinations || foundIndex[0] >= 0) return;

        // ── Build card bytes (max 16 bytes for a 16-digit card) ──────────
        // Store individual bytes in local variables (no heap in GPU kernels)
        byte c00=bin[0], c01=bin[1], c02=bin[2], c03=bin[3], c04=bin[4], c05=bin[5];
        // 9 free digit slots (for 16-digit card): indices 6..14
        long val = candidateIdx;
        byte c14=(byte)('0'+val%10); val/=10;
        byte c13=(byte)('0'+val%10); val/=10;
        byte c12=(byte)('0'+val%10); val/=10;
        byte c11=(byte)('0'+val%10); val/=10;
        byte c10=(byte)('0'+val%10); val/=10;
        byte c09=(byte)('0'+val%10); val/=10;
        byte c08=(byte)('0'+val%10); val/=10;
        byte c07=(byte)('0'+val%10); val/=10;
        byte c06=(byte)('0'+val%10);

        // ── Luhn check digit (position 15) ───────────────────────────────
        // Sum doubling from right (c14 is rightmost partial digit, gets doubled)
        static int D(byte b, bool dbl) { int v=(b-'0'); if(dbl){v*=2;if(v>9)v-=9;} return v; }
        int s = D(c14,true)+D(c13,false)+D(c12,true)+D(c11,false)+D(c10,true)
              + D(c09,false)+D(c08,true) +D(c07,false)+D(c06,true)
              + D(c05,false)+D(c04,true) +D(c03,false)+D(c02,true)
              + D(c01,false)+D(c00,true);
        byte c15 = (byte)('0' + (10 - s % 10) % 10);

        // ── Build salt || card input (max 48 bytes) ───────────────────────
        // Represent as up to 12 uint words for the padded block
        // Pack bytes big-endian: 4 bytes per uint
        // input = salt[0..saltLen-1] || c00..c15
        // For zero salt (saltLen=0): input = c00..c15 = 16 bytes
        // Pad to 64-byte SHA block
        //
        // We assemble input bytes into 16 uint words manually.
        // Support only saltLength == 0 or saltLength == 16 in this kernel for simplicity.
        // (The host ensures this constraint.)
        int inputLen = saltLength + cardLength;

        // Build all 16 bytes of card as a mini array using byte variables
        // Then pack into words alongside salt bytes
        // For inputLen <= 55, one block suffices
        uint pm0=0,pm1=0,pm2=0,pm3=0,pm4=0,pm5=0,pm6=0,pm7=0;
        uint pm8=0,pm9=0,pm10=0,pm11=0,pm12=0,pm13=0;
        // pm14 and pm15 carry bit-length
        uint pm14=0, pm15=(uint)(inputLen * 8);

        if (saltLength == 0)
        {
            // 16 bytes of card, starting at byte 0
            pm0 = ((uint)c00<<24)|((uint)c01<<16)|((uint)c02<<8)|c03;
            pm1 = ((uint)c04<<24)|((uint)c05<<16)|((uint)c06<<8)|c07;
            pm2 = ((uint)c08<<24)|((uint)c09<<16)|((uint)c10<<8)|c11;
            pm3 = ((uint)c12<<24)|((uint)c13<<16)|((uint)c14<<8)|c15;
            pm4 = 0x80000000u; // padding
        }
        else // saltLength == 16
        {
            // 16 salt bytes then 16 card bytes = 32 bytes total
            pm0 = ((uint)salt[0]<<24)|((uint)salt[1]<<16)|((uint)salt[2]<<8)|salt[3];
            pm1 = ((uint)salt[4]<<24)|((uint)salt[5]<<16)|((uint)salt[6]<<8)|salt[7];
            pm2 = ((uint)salt[8]<<24)|((uint)salt[9]<<16)|((uint)salt[10]<<8)|salt[11];
            pm3 = ((uint)salt[12]<<24)|((uint)salt[13]<<16)|((uint)salt[14]<<8)|salt[15];
            pm4 = ((uint)c00<<24)|((uint)c01<<16)|((uint)c02<<8)|c03;
            pm5 = ((uint)c04<<24)|((uint)c05<<16)|((uint)c06<<8)|c07;
            pm6 = ((uint)c08<<24)|((uint)c09<<16)|((uint)c10<<8)|c11;
            pm7 = ((uint)c12<<24)|((uint)c13<<16)|((uint)c14<<8)|c15;
            pm8 = 0x80000000u;
            pm15 = (uint)(32 * 8); // 256 bits
        }

        // ── Compute hash and compare ──────────────────────────────────────
        bool match;
        if (!useSha256)
        {
            GpuHash.Sha1(pm0,pm1,pm2,pm3,pm4,pm5,pm6,pm7,pm8,pm9,pm10,pm11,pm12,pm13,pm14,pm15,
                out uint h0,out uint h1,out uint h2,out uint h3,out uint h4);
            match = MatchSha1(targetHash, h0,h1,h2,h3,h4);
        }
        else
        {
            GpuHash.Sha256(pm0,pm1,pm2,pm3,pm4,pm5,pm6,pm7,pm8,pm9,pm10,pm11,pm12,pm13,pm14,pm15,
                out uint h0,out uint h1,out uint h2,out uint h3,
                out uint h4,out uint h5,out uint h6,out uint h7);
            match = MatchSha256(targetHash, h0,h1,h2,h3,h4,h5,h6,h7);
        }

        if (match && Atomic.CompareExchange(ref foundIndex[0], candidateIdx, -1L) == -1L)
        {
            // Write card bytes to output buffer
            foundCard[0]=c00; foundCard[1]=c01; foundCard[2]=c02; foundCard[3]=c03;
            foundCard[4]=c04; foundCard[5]=c05; foundCard[6]=c06; foundCard[7]=c07;
            foundCard[8]=c08; foundCard[9]=c09; foundCard[10]=c10; foundCard[11]=c11;
            foundCard[12]=c12; foundCard[13]=c13; foundCard[14]=c14; foundCard[15]=c15;
        }
    }

    private static bool MatchSha1(ArrayView1D<byte,Stride1D.Dense> target,
        uint h0,uint h1,uint h2,uint h3,uint h4)
    {
        return target[0]==(byte)(h0>>24) && target[1]==(byte)(h0>>16) &&
               target[2]==(byte)(h0>>8)  && target[3]==(byte)h0 &&
               target[4]==(byte)(h1>>24) && target[5]==(byte)(h1>>16) &&
               target[6]==(byte)(h1>>8)  && target[7]==(byte)h1 &&
               target[8]==(byte)(h2>>24) && target[9]==(byte)(h2>>16) &&
               target[10]==(byte)(h2>>8) && target[11]==(byte)h2 &&
               target[12]==(byte)(h3>>24)&& target[13]==(byte)(h3>>16) &&
               target[14]==(byte)(h3>>8) && target[15]==(byte)h3 &&
               target[16]==(byte)(h4>>24)&& target[17]==(byte)(h4>>16) &&
               target[18]==(byte)(h4>>8) && target[19]==(byte)h4;
    }

    private static bool MatchSha256(ArrayView1D<byte,Stride1D.Dense> target,
        uint h0,uint h1,uint h2,uint h3,uint h4,uint h5,uint h6,uint h7)
    {
        return MatchSha1(target, h0,h1,h2,h3,h4) &&
               target[20]==(byte)(h5>>24) && target[21]==(byte)(h5>>16) &&
               target[22]==(byte)(h5>>8)  && target[23]==(byte)h5 &&
               target[24]==(byte)(h6>>24) && target[25]==(byte)(h6>>16) &&
               target[26]==(byte)(h6>>8)  && target[27]==(byte)h6 &&
               target[28]==(byte)(h7>>24) && target[29]==(byte)(h7>>16) &&
               target[30]==(byte)(h7>>8)  && target[31]==(byte)h7;
    }
}
```

- [ ] **Step 2: Build GPU project**

```powershell
dotnet build CardHashDemo.Gpu
```
Expected: `Build succeeded.`

- [ ] **Step 3: Commit**

```powershell
git add CardHashDemo.Gpu/GpuCracker.cs
git commit -m "feat(gpu): implement ILGPU SHA1/SHA256 crack kernel with atomic first-match write"
```

---

## Task 13: GPU Program.cs

**Files:**
- Modify: `CardHashDemo.Gpu/Program.cs`

- [ ] **Step 1: Write GPU Program.cs**

`CardHashDemo.Gpu/Program.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;
using CardHashDemo.Gpu;
using ILGPU.Runtime.Cuda;

Console.OutputEncoding = Encoding.UTF8;
Console.Clear();

ConsoleHelper.PrintHeader("SHA1 / SHA256 Credit Card Hash Vulnerability Demo  [GPU — NVIDIA CUDA]");
ConsoleHelper.PrintWarning("EDUCATIONAL USE ONLY — authorized security testing / research");

// Verify CUDA is available before starting the narrative
try
{
    using var ctx = ILGPU.Context.CreateDefault();
    using var acc = ctx.CreateCudaAccelerator(0);
    ConsoleHelper.PrintSuccess($"CUDA device found: {acc.Name}  ({acc.MemorySize / 1024 / 1024} MB VRAM)");
}
catch (Exception ex)
{
    ConsoleHelper.PrintWarning($"No CUDA device available: {ex.Message}");
    ConsoleHelper.PrintInfo("Run CardHashDemo.Cpu on this machine instead.");
    return;
}

ConsoleHelper.Pause();

DemoSections.PrintSha1Explainer();
ConsoleHelper.Pause();
DemoSections.PrintLuhnSection();
ConsoleHelper.Pause();
DemoSections.PrintBinSection();
ConsoleHelper.Pause();

// Generate target — pick a random 16-digit Israeli BIN
ConsoleHelper.PrintSection("Generating Target Card");
var sixteenDigitBins = IsraeliCards.KnownBins.Where(b => b.CardLength == 16).ToList();
var bin = sixteenDigitBins[Random.Shared.Next(sixteenDigitBins.Count)];

string card       = IsraeliCards.GenerateCard(bin);
byte[] cardAscii  = Encoding.ASCII.GetBytes(card);
// GPU kernel supports saltLength 0 or 16 only — use exactly 16-byte salts
byte[] staticSalt = Encoding.ASCII.GetBytes("Pepper16ByteKey!"); // exactly 16 bytes
byte[] perCardSalt = new byte[16];
Random.Shared.NextBytes(perCardSalt);

string sha1Hash     = Convert.ToHexString(SHA1.HashData(cardAscii));
string sha256Hash   = Convert.ToHexString(SHA256.HashData(cardAscii));
string sha256Stat   = Convert.ToHexString(SHA256.HashData([..staticSalt, ..cardAscii]));
string sha256PerC   = Convert.ToHexString(SHA256.HashData([..perCardSalt, ..cardAscii]));

ConsoleHelper.PrintHighlight("Generated card", card);
ConsoleHelper.PrintHighlight("BIN", $"{bin.Prefix} — {bin.Issuer}");
ConsoleHelper.PrintHighlight("SHA1(PAN)", sha1Hash);
ConsoleHelper.PrintHighlight("SHA256(PAN)", sha256Hash);
ConsoleHelper.PrintHighlight("SHA256(static-salt+PAN)", sha256Stat);
ConsoleHelper.PrintHighlight("SHA256(per-card-salt+PAN)", sha256PerC);
ConsoleHelper.Pause("Press any key to start GPU cracking...");

var gpuProgress = new Progress<(long tried, long total, TimeSpan elapsed)>(p =>
{
    double pct = p.total > 0 ? p.tried * 100.0 / p.total : 0;
    double ghps = p.elapsed.TotalSeconds > 0 ? p.tried / p.elapsed.TotalSeconds / 1e9 : 0;
    Console.Write($"\r  [{pct,6:F2}%] {p.tried,13:N0} / {p.total:N0}  {ghps,6:F2} G/sec  {p.elapsed:hh\\:mm\\:ss\\.ff}   ");
});

var results = new List<(string Algorithm, TimeSpan Elapsed, double GHashSec)>();

void RunAttack(string label, string hash, bool sha256, byte[] salt)
{
    ConsoleHelper.PrintSection($"Attack — {label}");
    var r = GpuCracker.Crack(hash, bin, sha256, salt, gpuProgress);
    Console.WriteLine();
    ConsoleHelper.PrintResultRow("Algorithm",    label);
    ConsoleHelper.PrintResultRow("Card found",   r.Card ?? "(not found)");
    if (r.Card == card) ConsoleHelper.PrintSuccess("Matches original card ✓");
    ConsoleHelper.PrintResultRow("Elapsed",      r.Elapsed.ToString(@"hh\:mm\:ss\.fff"));
    ConsoleHelper.PrintResultRow("Speed",        $"{r.GHashSec:F2} G hash/sec");
    ConsoleHelper.PrintResultRow("Combinations", $"{r.Tried:N0} / {r.Total:N0}");
    results.Add((label, r.Elapsed, r.GHashSec));
    ConsoleHelper.Pause();
}

RunAttack("SHA1 (no salt)",              sha1Hash,    false, []);
RunAttack("SHA256 (no salt)",            sha256Hash,  true,  []);
RunAttack("SHA256 (static salt)",        sha256Stat,  true,  staticSalt);
RunAttack("SHA256 (per-card salt 16B)",  sha256PerC,  true,  perCardSalt);

// Comparison table
ConsoleHelper.PrintSection("GPU Summary");
ConsoleHelper.PrintHighlight("Original card", card);
Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine($"  {"Algorithm",-42} │ {"Elapsed",13} │ {"Speed",12}");
Console.WriteLine($"  {new string('─', 72)}");
foreach (var (alg, elapsed, ghps) in results)
    Console.WriteLine($"  {alg,-42} │ {elapsed,13:hh\\:mm\\:ss\\.fff} │ {ghps,9:F2} G/sec");
Console.ResetColor();
Console.WriteLine();
ConsoleHelper.PrintWarning("Salt defeats rainbow tables. It does NOT defeat brute force.");
ConsoleHelper.PrintWarning("The fix: use Argon2id or bcrypt with an appropriate work factor.");

DemoSections.PrintTrack2Section();
ConsoleHelper.Pause();
DemoSections.PrintTakeaways();
```

- [ ] **Step 2: Build**

```powershell
dotnet build CardHashDemo.Gpu
```
Expected: `Build succeeded.`

- [ ] **Step 3: Final test run**

```powershell
dotnet test CardHashDemo.Tests
```
Expected: all tests pass.

- [ ] **Step 4: Final commit**

```powershell
git add CardHashDemo.Gpu/Program.cs
git commit -m "feat(gpu): implement GPU demo flow with CUDA accelerator and early-exit on match"
```

---

## Running the Apps

```powershell
# CPU version (works on any machine)
dotnet run --project CardHashDemo.Cpu

# GPU version (requires NVIDIA CUDA GPU)
dotnet run --project CardHashDemo.Gpu
```

Copy the entire `CardHashDemo.Gpu/` folder plus `CardHashDemo.Core/` to your second PC to run the GPU version independently. Or just copy the published binaries:
```powershell
dotnet publish CardHashDemo.Gpu -c Release -o publish/gpu
# Copy publish/gpu/ to second PC and run CardHashDemo.Gpu.exe
```
