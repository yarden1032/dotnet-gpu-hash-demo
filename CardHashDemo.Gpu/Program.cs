using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;
using CardHashDemo.Gpu;
using ILGPU.Runtime.Cuda;

Console.OutputEncoding = Encoding.UTF8;
ConsoleHelper.Clear();

ConsoleHelper.PrintHeader("SHA1 / SHA256 Credit Card Hash Vulnerability Demo  [GPU — NVIDIA CUDA]");
ConsoleHelper.PrintWarning("EDUCATIONAL USE ONLY — authorized security testing / research");

// ── Detect GPU: CUDA first, then OpenCL, exit if neither ─────────────────
// Detect all usable GPU backends. Detection also compiles the actual crack
// kernel, so a listed option means the GPU can run this demo's kernel, not just
// that Windows can see a display adapter.
var gpuOptions = GpuCracker.DetectAvailableGpus(out var skippedGpuOptions);
if (gpuOptions.Count == 0)
{
    ConsoleHelper.PrintWarning("No GPU found (tried CUDA and OpenCL).");
    PrintSkippedGpuOptions(skippedGpuOptions);
    ConsoleHelper.PrintInfo("Run CardHashDemo.Cpu on this machine instead.");
    return;
}
PrintSkippedGpuOptions(skippedGpuOptions);
var gpuDevice = SelectGpuBackend(gpuOptions);
ConsoleHelper.PrintSuccess($"GPU selected: {gpuDevice.DeviceInfo}");

ConsoleHelper.Pause();

DemoSections.PrintSha1Explainer();
ConsoleHelper.Pause();
DemoSections.PrintLuhnSection();
ConsoleHelper.Pause();
DemoSections.PrintBinSection();
ConsoleHelper.Pause();

// ── Generate target card ──────────────────────────────────────────────────
ConsoleHelper.PrintSection("Generating Target Card");

// The GPU kernel is intentionally optimized for the common 16-digit
// Visa/Mastercard shape: 6 BIN digits, 9 searched digits, and 1 Luhn digit
// generated inside the kernel.
var sixteenBins = IsraeliCards.KnownBins.Where(b => b.CardLength == 16).ToList();
var bin = sixteenBins[Random.Shared.Next(sixteenBins.Count)];
string card = IsraeliCards.GenerateCard(bin);

ConsoleHelper.PrintHighlight("Card (stored in payment system)", card);
ConsoleHelper.PrintHighlight("BIN", $"{bin.Prefix} — {bin.Issuer}");

byte[] cardAscii   = Encoding.ASCII.GetBytes(card);
// GPU kernel handles saltLength 0 or 16 — keep salts exactly 16 bytes
// Keeping salts exactly 16 bytes lets the kernel build one fixed SHA block
// without loops, dynamic arrays, or heap allocation.
byte[] staticSalt  = Encoding.ASCII.GetBytes("Pepper16ByteKey!"); // exactly 16 bytes
byte[] perCardSalt = new byte[16];
Random.Shared.NextBytes(perCardSalt);

string sha1Hash      = Convert.ToHexString(SHA1.HashData(cardAscii));
string sha256Hash    = Convert.ToHexString(SHA256.HashData(cardAscii));
string sha256Static  = Convert.ToHexString(SHA256.HashData([.. staticSalt,  .. cardAscii]));
string sha256PerCard = Convert.ToHexString(SHA256.HashData([.. perCardSalt, .. cardAscii]));

Console.WriteLine();
ConsoleHelper.PrintHighlight("SHA1(PAN)                   → DB", sha1Hash);
ConsoleHelper.PrintHighlight("SHA256(PAN)                 → DB", sha256Hash);
ConsoleHelper.PrintHighlight("SHA256(static-salt + PAN)   → DB", sha256Static);
ConsoleHelper.PrintHighlight("SHA256(per-card-salt + PAN) → DB", sha256PerCard);
ConsoleHelper.PrintHighlight("Per-card salt (also in DB row)",   Convert.ToHexString(perCardSalt));

Console.WriteLine();
ConsoleHelper.PrintInfo("Original card number is now 'forgotten'...");
ConsoleHelper.Pause("Press any key to start GPU cracking...");

var gpuProg = new Progress<(long tried, long total, TimeSpan elapsed)>(p =>
{
    double pct  = p.total > 0 ? p.tried * 100.0 / p.total : 0;
    double ghps = p.elapsed.TotalSeconds > 0 ? p.tried / p.elapsed.TotalSeconds / 1e9 : 0;
    Console.Write($"\r  [{pct,6:F2}%] {p.tried,13:N0} / {p.total:N0}  {ghps,6:F2} G/sec  {p.elapsed:hh\\:mm\\:ss\\.ff}   ");
});

var results = new List<(string Algorithm, TimeSpan Elapsed, double GHashSec)>();
var attacks = new List<AttackResult>();

void RunAttack(string label, string hash, bool sha256, byte[] salt)
{
    ConsoleHelper.PrintSection($"Attack — {label}");
    // The CPU passes only the target hash, BIN, algorithm flag, and salt.
    // GpuCracker.Crack does the full candidate search on the GPU and returns
    // the first card whose GPU-computed digest matches this target hash.
    var r = GpuCracker.Crack(hash, bin, sha256, salt, gpuDevice, gpuProg);
    Console.WriteLine();
    ConsoleHelper.PrintResultRow("Algorithm",          label);
    ConsoleHelper.PrintResultRow("Card found",         r.Card ?? "(not found)");
    if (r.Card == card) ConsoleHelper.PrintSuccess("Matches the original card ✓");
    else                ConsoleHelper.PrintWarning("Mismatch — check output!");
    ConsoleHelper.PrintResultRow("Elapsed",            r.Elapsed.ToString(@"hh\:mm\:ss\.fff"));
    ConsoleHelper.PrintResultRow("Speed",              $"{r.GHashSec:F3} G hash/sec");
    ConsoleHelper.PrintResultRow("Combinations tried", $"{r.Tried:N0} / {r.Total:N0}");
    results.Add((label, r.Elapsed, r.GHashSec));
    // Store speed in M/sec convention (GHashSec × 1000) so Track2 math is uniform
    attacks.Add(new AttackResult(label, r.Elapsed, r.GHashSec * 1000.0, r.Tried, r.Total));
    ConsoleHelper.Pause();
}

try
{
    RunAttack("SHA1  (no salt)",             sha1Hash,      false, []);
    RunAttack("SHA256 (no salt)",            sha256Hash,    true,  []);
    RunAttack("SHA256 (static salt 16 B)",   sha256Static,  true,  staticSalt);
    RunAttack("SHA256 (per-card salt 16 B)", sha256PerCard, true,  perCardSalt);
}
catch (NotSupportedException ex)
{
    Console.WriteLine();
    ConsoleHelper.PrintWarning(ex.Message);
    ConsoleHelper.PrintInfo("Run CardHashDemo.Cpu on this machine instead.");
    return;
}

// ── GPU comparison table ──────────────────────────────────────────────────
ConsoleHelper.PrintSection("GPU Summary");
ConsoleHelper.PrintHighlight("Original card", card);
Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine($"  {"Algorithm",-38} │ {"Elapsed",13} │ {"Speed",12}");
Console.WriteLine($"  {new string('─', 68)}");
foreach (var (alg, elapsed, ghps) in results)
    Console.WriteLine($"  {alg,-38} │ {elapsed,13:hh\\:mm\\:ss\\.fff} │ {ghps,9:F3} G/sec");
Console.ResetColor();
Console.WriteLine();
ConsoleHelper.PrintWarning("Salt defeats rainbow tables. It does NOT defeat brute force on a small input space.");
ConsoleHelper.PrintWarning("Fix: use Argon2id or bcrypt with a work factor.");

DemoSections.PrintTrack2Section(attacks, isGpu: true);
ConsoleHelper.Pause();
DemoSections.PrintTakeaways();

// ── Write summary file ────────────────────────────────────────────────────
string gpuDeviceName = gpuDevice.DeviceInfo; // already captured at startup

var summary = new ResultSummary
{
    MachineType  = "GPU",
    HardwareInfo = gpuDeviceName,
    RunAt        = DateTime.Now,
    Card         = card,
    BinPrefix    = bin.Prefix,
    BinIssuer    = bin.Issuer,
    Attacks      = attacks,
};
string summaryPath = summary.Write();
Console.WriteLine();
ConsoleHelper.PrintSuccess($"Summary written to: {summaryPath}");

// ── Check if CPU summary exists ───────────────────────────────────────────
string? cpuText = ResultSummary.TryReadCounterpart("GPU");
if (cpuText is not null)
{
    ConsoleHelper.PrintSection("CPU Summary Found — Comparison");
    ConsoleHelper.PrintInfo("Content of summary-cpu.txt:");
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(cpuText);
    Console.ResetColor();
}
else
{
    ConsoleHelper.PrintInfo("No summary-cpu.txt found yet. Run CardHashDemo.Cpu on your CPU machine,");
    ConsoleHelper.PrintInfo("then copy summary-cpu.txt here to see the side-by-side comparison.");
}

static GpuDeviceOption SelectGpuBackend(IReadOnlyList<GpuDeviceOption> options)
{
    ConsoleHelper.PrintSection("Select GPU Backend");
    for (int i = 0; i < options.Count; i++)
        ConsoleHelper.PrintInfo($"{i + 1}. {options[i].DeviceInfo}");

    if (options.Count == 1)
    {
        ConsoleHelper.PrintInfo("Only one usable backend was found; selecting it automatically.");
        return options[0];
    }

    if (Console.IsInputRedirected)
    {
        ConsoleHelper.PrintInfo("Input is redirected; selecting option 1 automatically.");
        return options[0];
    }

    while (true)
    {
        Console.Write($"  Choose backend [1-{options.Count}]: ");
        string? input = Console.ReadLine();
        if (int.TryParse(input, out int choice) && choice >= 1 && choice <= options.Count)
            return options[choice - 1];

        ConsoleHelper.PrintWarning($"Please enter a number between 1 and {options.Count}.");
    }
}

static void PrintSkippedGpuOptions(IReadOnlyList<GpuDetectionIssue> skippedGpuOptions)
{
    if (skippedGpuOptions.Count == 0)
        return;

    ConsoleHelper.PrintSection("Unavailable GPU Options");
    foreach (var skipped in skippedGpuOptions)
        ConsoleHelper.PrintWarning($"{skipped.DeviceInfo} skipped: {skipped.Reason}");
}
