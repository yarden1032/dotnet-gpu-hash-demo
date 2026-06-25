using System.Text;

namespace CardHashDemo.Core;

/// <summary>Holds the full results of one demo run and can write/read a summary file.</summary>
public record AttackResult(string Algorithm, TimeSpan Elapsed, double HashesPerSecond, long Tried, long Total);

public class ResultSummary
{
    public string MachineType { get; init; } = "";   // "CPU" or "GPU"
    public string HardwareInfo { get; init; } = "";  // e.g. "16 cores" or "RTX 3080 8192 MB"
    public DateTime RunAt { get; init; }
    public string Card { get; init; } = "";
    public string BinPrefix { get; init; } = "";
    public string BinIssuer { get; init; } = "";
    public IReadOnlyList<AttackResult> Attacks { get; init; } = [];

    // Track 2 constants
    public const long PanCombinations      = 1_000_000_000L;
    public const long UnknownBinMultiplier = 10_000_000L;
    public const int  ExpiryDatesAll       = 72;   // 6 years x 12 months
    public const int  ExpiryDatesKnownYear = 12;
    public const int  ServiceCodes         = 15;

    public static long Track2Full      => PanCombinations * ExpiryDatesAll       * ServiceCodes;
    public static long Track2KnownYear => PanCombinations * ExpiryDatesKnownYear * ServiceCodes;
    public static double PanUnknownBin => PanCombinations * (double)UnknownBinMultiplier;
    public static double Track2FullUnknownBin => Track2Full * (double)UnknownBinMultiplier;
    public static double Track2KnownYearUnknownBin => Track2KnownYear * (double)UnknownBinMultiplier;

    // Write
    public string Write()
    {
        string filename = $"summary-{MachineType.ToLowerInvariant()}.txt";
        string path     = Path.Combine(Directory.GetCurrentDirectory(), filename);

        var sb = new StringBuilder();
        string bar = new('=', 70);
        sb.AppendLine(bar);
        sb.AppendLine($"  CardHashDemo - SHA Hash Vulnerability Results");
        sb.AppendLine($"  Mode     : {MachineType}");
        sb.AppendLine($"  Hardware : {HardwareInfo}");
        sb.AppendLine($"  Date     : {RunAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Target   : {Card}  (BIN {BinPrefix} - {BinIssuer})");
        sb.AppendLine(bar);
        sb.AppendLine();

        sb.AppendLine("[PAN Cracking Results]");
        sb.AppendLine($"  {"Algorithm",-38} {"Elapsed",13}   {"Speed",14}   Combinations");
        sb.AppendLine($"  {new string('-', 85)}");
        foreach (var a in Attacks)
        {
            string speed = MachineType == "GPU"
                ? $"{a.HashesPerSecond / 1000.0:F3} G/sec"
                : $"{a.HashesPerSecond:F1} M/sec";
            sb.AppendLine($"  {a.Algorithm,-38} {a.Elapsed,13:hh\\:mm\\:ss\\.fff}   {speed,14}   {a.Tried:N0}");
        }
        sb.AppendLine();

        sb.AppendLine("[Track 2 Estimated Crack Times]");
        sb.AppendLine($"  Space (full Track2)       : {Track2Full:N0}  (10^9 PAN x {ExpiryDatesAll} expiry x {ServiceCodes} service codes)");
        sb.AppendLine($"  Space (known expiry year) : {Track2KnownYear:N0}  (10^9 PAN x {ExpiryDatesKnownYear} months x {ServiceCodes} service codes)");
        sb.AppendLine();
        sb.AppendLine($"  {"Algorithm",-38} {"Full Track2",15}   {"Known expiry year",18}");
        sb.AppendLine($"  {new string('-', 76)}");
        foreach (var a in Attacks)
        {
            double hps = MachineType == "GPU" ? a.HashesPerSecond * 1_000_000.0 : a.HashesPerSecond * 1_000_000.0;
            string t1  = FormatDuration(Track2Full      / hps);
            string t2  = FormatDuration(Track2KnownYear / hps);
            sb.AppendLine($"  {a.Algorithm,-38} {t1,15}   {t2,18}");
        }
        sb.AppendLine();

        sb.AppendLine("[No BIN Known Estimated Crack Times]");
        sb.AppendLine($"  Assumption: no 6-digit BIN is known, so the search is about {UnknownBinMultiplier:N0}x larger than one known BIN.");
        sb.AppendLine($"  Space (PAN only, no BIN)       : {PanUnknownBin:N0}  (10^16 possible 16-digit PAN values)");
        sb.AppendLine($"  Space (full Track2, no BIN)    : {Track2FullUnknownBin:N0}");
        sb.AppendLine($"  Space (known expiry year)      : {Track2KnownYearUnknownBin:N0}");
        sb.AppendLine();
        sb.AppendLine($"  {"Algorithm",-38} {"PAN only",15}   {"Full Track2",15}   {"Known expiry year",18}");
        sb.AppendLine($"  {new string('-', 96)}");
        foreach (var a in Attacks)
        {
            double hps = a.HashesPerSecond * 1_000_000.0;
            string panOnly = FormatDuration(PanUnknownBin / hps);
            string fullTrack2 = FormatDuration(Track2FullUnknownBin / hps);
            string knownYear = FormatDuration(Track2KnownYearUnknownBin / hps);
            sb.AppendLine($"  {a.Algorithm,-38} {panOnly,15}   {fullTrack2,15}   {knownYear,18}");
        }
        sb.AppendLine();
        sb.AppendLine("  Note: these are estimates based on the measured PAN cracking speed on this machine.");

        File.WriteAllText(path, sb.ToString());
        return path;
    }

    // Read
    public static string? TryReadCounterpart(string myMachineType)
    {
        string other    = myMachineType == "CPU" ? "gpu" : "cpu";
        string filename = $"summary-{other}.txt";
        string path     = Path.Combine(Directory.GetCurrentDirectory(), filename);
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    // Helpers
    public static string FormatDuration(double seconds)
    {
        if (seconds < 60)           return $"{seconds:F1}s";
        if (seconds < 3600)         return $"{seconds / 60:F1}m  ({TimeSpan.FromSeconds(seconds):mm\\:ss})";
        if (seconds < 86400)        return $"{TimeSpan.FromSeconds(seconds):h\\h\\ mm\\m\\ ss\\s}";
        double days = seconds / 86400;
        if (days < 365)             return $"{days:F1} days";
        double years = days / 365.2425;
        return years < 1000 ? $"{years:F1} years" : $"{years:N0} years";
    }
}
